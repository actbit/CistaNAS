using System.Collections.Concurrent;
using System.Security.Cryptography;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Crypto;
using CistaNAS.Web.Identity;
using CistaNAS.Web.Models;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// ボリュームの作成・マウント・ロック・共有を管理する Singleton Service。
/// メタデータは VolumeMetadataStore（IStorageProvider）経由で保存し、
/// volume.dat はローカルファイルシステムに配置。
/// </summary>
public sealed class VolumeService
{
    private readonly string _volumeDataPath;
    private readonly VolumeOptions _volOpts;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly VolumeMetadataStore _metaStore;

    private readonly ConcurrentDictionary<string, MountedVolume> _mounted = new();
    private readonly SemaphoreSlim _mountGate = new(1, 1);

    public VolumeService(IOptions<CistaNasOptions> options, IServiceScopeFactory scopeFactory, VolumeMetadataStore metaStore)
    {
        _volumeDataPath = options.Value.Storage.VolumeDataPath ?? options.Value.DataRoot;
        _volOpts = options.Value.Volume;
        _scopeFactory = scopeFactory;
        _metaStore = metaStore;
        Directory.CreateDirectory(_volumeDataPath);
    }

    public VolumeInfo Create(string name, string? username, string? password, bool encrypted = true)
    {
        ValidateName(name);
        _mountGate.Wait();
        try
        {
            return CreateInternal(name, username, password, encrypted);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    /// <summary>ホームボリューム等、内部用途の作成（home__ プレフィックスを許可）。</summary>
    public VolumeInfo CreateInternal(string name, string? username, string? password, bool encrypted = true)
    {
        if (encrypted) { ArgumentException.ThrowIfNullOrEmpty(username); ArgumentException.ThrowIfNullOrEmpty(password); }

        if (_metaStore.ExistsAsync(name).GetAwaiter().GetResult())
            throw new VolumeException($"ボリューム '{name}' は既に存在します。");

        var (header, masterKey) = VolumeHeader.Create(name, username, password, _volOpts.SectorSize, _volOpts.KdfIterations, encrypted);

        Directory.CreateDirectory(VolumeDir(name));
        _metaStore.SaveAsync(name, header).GetAwaiter().GetResult();
        File.Create(GetDataPath(name)).Dispose();
        MountInternal(name, header, masterKey);

        return ToInfo(name, header, true);
    }

    /// <summary>E2EE ボリュームを作成（クライアントから wrappedMasterKey を受け取る）。</summary>
    public VolumeInfo CreateE2ee(string name, string username, VolumeHeader.UserWrappedKey wrappedKey, int chunkSize = 1048576)
    {
        ValidateName(name);
        ArgumentException.ThrowIfNullOrEmpty(username);

        _mountGate.Wait();
        try
        {
            if (_metaStore.ExistsAsync(name).GetAwaiter().GetResult())
                throw new VolumeException($"ボリューム '{name}' は既に存在します。");

            var header = VolumeHeader.CreateE2ee(name, username, wrappedKey, chunkSize);

            Directory.CreateDirectory(VolumeDir(name));
            _metaStore.SaveAsync(name, header).GetAwaiter().GetResult();
            File.Create(GetDataPath(name)).Dispose();
            MountInternal(name, header, masterKey: null);

            return ToInfo(name, header, true);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    public VolumeInfo Mount(string name, string username, string? password)
    {
        _mountGate.Wait();
        try
        {
            if (_mounted.ContainsKey(name))
                throw new VolumeException($"ボリューム '{name}' は既にマウントされています。");

            var header = LoadHeaderOrThrow(name);
            byte[]? masterKey = null;
            if (header.Encrypted)
            {
                ArgumentException.ThrowIfNullOrEmpty(username);
                ArgumentException.ThrowIfNullOrEmpty(password);
                masterKey = header.UnwrapMasterKey(username, password)
                    ?? throw new VolumeException("認証情報が正しくありません。");
            }

            MountInternal(name, header, masterKey);
            return ToInfo(name, header, true);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    /// <summary>E2EE ボリュームをマウント（アクセス権チェックのみ、鍵アンラップなし）。</summary>
    public VolumeInfo MountE2ee(string name, string username)
    {
        _mountGate.Wait();
        try
        {
            if (_mounted.ContainsKey(name))
                throw new VolumeException($"ボリューム '{name}' は既にマウントされています。");

            var header = LoadHeaderOrThrow(name);
            if (!header.IsE2ee)
                throw new VolumeException($"ボリューム '{name}' は E2EE ボリュームではありません。");
            if (!header.HasUserAccess(username))
                throw new VolumeException($"ユーザー '{username}' はこのボリュームにアクセス権がありません。");

            MountInternal(name, header, masterKey: null);
            return ToInfo(name, header, true);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    /// <summary>E2EE ボリュームに wrapped key を追加（クライアント側で再ラップ済み）。</summary>
    public void AddE2eeWrappedKey(string volumeName, string granterUsername, string targetUsername, VolumeHeader.UserWrappedKey wrappedKey)
    {
        _mountGate.Wait();
        try
        {
            var header = LoadHeaderOrThrow(volumeName);
            if (!header.IsE2ee)
                throw new VolumeException($"ボリューム '{volumeName}' は E2EE ボリュームではありません。");
            if (header.OwnerUser != granterUsername)
                throw new VolumeException("オーナーのみがアクセス権を付与できます。");
            if (!header.HasUserAccess(targetUsername))
                header.AddWrappedKey(targetUsername, wrappedKey);
            _metaStore.SaveAsync(volumeName, header).GetAwaiter().GetResult();
            RefreshMountedHeader(volumeName, header);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    public void Lock(string name)
    {
        _mountGate.Wait();
        try
        {
            if (!_mounted.TryRemove(name, out var mv))
                throw new VolumeException($"ボリューム '{name}' はマウントされていません。");
            mv.Stream.Dispose();
            if (mv.MasterKey is not null) CryptographicOperations.ZeroMemory(mv.MasterKey);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    /// <summary>ボリューム情報を返す。存在しない場合は null。</summary>
    public VolumeInfo? GetVolumeInfo(string name)
    {
        var header = LoadHeaderIfExists(name);
        if (header is null) return null;
        return ToInfo(name, header, _mounted.ContainsKey(name));
    }

    /// <summary>ボリュームヘッダを返す。存在しない場合は例外。</summary>
    public VolumeHeader GetVolumeHeader(string name) => LoadHeaderOrThrow(name);

    /// <summary>指定ユーザーがアクセスできるボリューム一覧を返す。</summary>
    public IReadOnlyList<VolumeInfo> ListForUser(string username)
    {
        var result = new List<VolumeInfo>();
        var volumeNames = _metaStore.ListVolumeNamesAsync().GetAwaiter().GetResult();

        var userGroups = GetGroupsForUser(username);

        foreach (var name in volumeNames)
        {
            var header = LoadHeaderIfExists(name);
            if (header is null) continue;

            if (!HasAccessInternal(header, username, userGroups)) continue;

            result.Add(ToInfo(name, header, _mounted.ContainsKey(name)));
        }
        return result;
    }

    public IReadOnlyList<VolumeInfo> ListAll()
    {
        var result = new List<VolumeInfo>();
        var volumeNames = _metaStore.ListVolumeNamesAsync().GetAwaiter().GetResult();

        foreach (var name in volumeNames)
        {
            var header = LoadHeaderIfExists(name);
            if (header is null) continue;
            result.Add(ToInfo(name, header, _mounted.ContainsKey(name)));
        }
        return result;
    }

    public (Stream Stream, VolumeHeader Header) GetMounted(string name)
    {
        if (!_mounted.TryGetValue(name, out var mv))
            throw new VolumeException($"ボリューム '{name}' はマウントされていません。");
        return (mv.Stream, mv.Header);
    }

    public bool IsMounted(string name) => _mounted.ContainsKey(name);

    /// <summary>ボリュームが指定ユーザーのアクセス権を持つか。</summary>
    public bool HasAccess(string volumeName, string username)
    {
        var header = LoadHeaderIfExists(volumeName);
        if (header is null) return false;
        var userGroups = GetGroupsForUser(username);
        return HasAccessInternal(header, username, userGroups);
    }

    private static bool HasAccessInternal(VolumeHeader header, string username, HashSet<string> userGroups)
    {
        // 非暗号化ボリューム: UserKeys が空なら誰でもアクセス可、そうでなければユーザーまたはグループ
        if (!header.Encrypted && header.UserKeys.Count == 0) return true;
        if (header.HasUserAccess(username)) return true;
        if (header.AuthorizedGroups.Overlaps(userGroups)) return true;
        return false;
    }

    // ---- 共有 ----

    /// <summary>ボリュームに別ユーザーのアクセス権を付与。</summary>
    public void GrantAccess(string volumeName, string granterUsername, string granterPassword,
        string targetUsername, string targetPassword)
    {
        ArgumentException.ThrowIfNullOrEmpty(granterUsername);
        ArgumentException.ThrowIfNullOrEmpty(granterPassword);
        ArgumentException.ThrowIfNullOrEmpty(targetUsername);
        ArgumentException.ThrowIfNullOrEmpty(targetPassword);

        _mountGate.Wait();
        try
        {
            var header = LoadHeaderOrThrow(volumeName);
            if (!header.HasUserAccess(granterUsername))
                throw new VolumeException($"ユーザー '{granterUsername}' はこのボリュームにアクセス権がありません。");

            byte[]? masterKey = header.UnwrapMasterKey(granterUsername, granterPassword)
                ?? throw new VolumeException("付与者の認証情報が正しくありません。");

            try
            {
                header.AddUserWrap(targetUsername, targetPassword, masterKey, _volOpts.KdfIterations);
                _metaStore.SaveAsync(volumeName, header).GetAwaiter().GetResult();
                RefreshMountedHeader(volumeName, header);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(masterKey);
            }
        }
        finally
        {
            _mountGate.Release();
        }
    }

    /// <summary>ボリュームからユーザーのアクセス権を剥奪。</summary>
    public void RevokeAccess(string volumeName, string revokerUsername, string targetUsername)
    {
        _mountGate.Wait();
        try
        {
            var header = LoadHeaderOrThrow(volumeName);
            if (header.OwnerUser != revokerUsername)
                throw new VolumeException("オーナーのみがアクセス権を剥奪できます。");
            if (targetUsername == header.OwnerUser)
                throw new VolumeException("オーナーのアクセス権は剥奪できません。");

            header.RemoveUserWrap(targetUsername);
            _metaStore.SaveAsync(volumeName, header).GetAwaiter().GetResult();
            RefreshMountedHeader(volumeName, header);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    /// <summary>ユーザーのパスワード変更時に全ボリュームの鍵を再ラップ。</summary>
    public void RewrapAllForUser(string username, string oldPassword, string newPassword)
    {
        var volumeNames = _metaStore.ListVolumeNamesAsync().GetAwaiter().GetResult();

        _mountGate.Wait();
        try
        {
            foreach (var name in volumeNames)
            {
                var header = LoadHeaderIfExists(name);
                if (header is null || !header.HasUserAccess(username)) continue;

                header.RewrapUser(username, oldPassword, newPassword, _volOpts.KdfIterations);
                _metaStore.SaveAsync(name, header).GetAwaiter().GetResult();
                RefreshMountedHeader(name, header);
            }
        }
        finally
        {
            _mountGate.Release();
        }
    }

    // ---- グループアクセス ----

    public void GrantGroupAccess(string volumeName, string granterUsername, string groupName)
    {
        _mountGate.Wait();
        try
        {
            var header = LoadHeaderOrThrow(volumeName);
        if (header.OwnerUser != granterUsername)
            throw new VolumeException("オーナーのみがグループアクセスを付与できます。");
        if (header.IsE2ee)
            throw new VolumeException("E2EE ボリュームはグループ共有に対応していません。");
        if (FindGroup(groupName) is null)
            throw new VolumeException($"グループ '{groupName}' が見つかりません。");

            header.AuthorizedGroups.Add(groupName);
            _metaStore.SaveAsync(volumeName, header).GetAwaiter().GetResult();
            RefreshMountedHeader(volumeName, header);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    public void RevokeGroupAccess(string volumeName, string revokerUsername, string groupName)
    {
        _mountGate.Wait();
        try
        {
            var header = LoadHeaderOrThrow(volumeName);
            if (header.OwnerUser != revokerUsername)
                throw new VolumeException("オーナーのみがグループアクセスを剥奪できます。");
            if (!header.AuthorizedGroups.Remove(groupName))
                throw new VolumeException($"グループ '{groupName}' はこのボリュームにアクセス権がありません。");

            _metaStore.SaveAsync(volumeName, header).GetAwaiter().GetResult();
            RefreshMountedHeader(volumeName, header);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    public void RemoveGroupFromAllVolumes(string groupName)
    {
        var volumeNames = _metaStore.ListVolumeNamesAsync().GetAwaiter().GetResult();

        _mountGate.Wait();
        try
        {
            foreach (var name in volumeNames)
            {
                var header = LoadHeaderIfExists(name);
                if (header is null) continue;
                if (header.AuthorizedGroups.Remove(groupName))
                {
                    _metaStore.SaveAsync(name, header).GetAwaiter().GetResult();
                    RefreshMountedHeader(name, header);
                }
            }
        }
        finally
        {
            _mountGate.Release();
        }
    }

    // ---- グループ E2EE ボリューム ----

    /// <summary>グループ専用E2EEボリュームを作成（group__ プレフィックス付き）。</summary>
    public VolumeInfo CreateGroupE2ee(string groupName, string ownerUsername,
        VolumeHeader.UserWrappedKey ownerWrappedKey, int chunkSize = 1048576)
    {
        ArgumentException.ThrowIfNullOrEmpty(groupName);
        ArgumentException.ThrowIfNullOrEmpty(ownerUsername);

        _mountGate.Wait();
        try
        {
            if (FindGroup(groupName) is null)
                throw new VolumeException($"グループ '{groupName}' が見つかりません。");

            string volName = $"group__{groupName}";
            if (_metaStore.ExistsAsync(volName).GetAwaiter().GetResult())
                throw new VolumeException($"グループボリューム '{volName}' は既に存在します。");

            var header = VolumeHeader.CreateE2ee(volName, ownerUsername, ownerWrappedKey, chunkSize);

            Directory.CreateDirectory(VolumeDir(volName));
            _metaStore.SaveAsync(volName, header).GetAwaiter().GetResult();
            File.Create(GetDataPath(volName)).Dispose();
            MountInternal(volName, header, masterKey: null);

            return ToInfo(volName, header, true);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    /// <summary>グループのE2EEボリューム一覧を取得（グループオーナー用）。</summary>
    public IReadOnlyList<VolumeInfo> GetGroupE2eeVolumes(string groupName)
    {
        var result = new List<VolumeInfo>();
        string prefix = $"group__{groupName}";
        var volumeNames = _metaStore.ListVolumeNamesAsync().GetAwaiter().GetResult();

        foreach (var name in volumeNames)
        {
            if (name != prefix) continue;
            var header = LoadHeaderIfExists(name);
            if (header is null || !header.IsE2ee) continue;
            result.Add(ToInfo(name, header, _mounted.ContainsKey(name)));
        }
        return result;
    }

    /// <summary>グループメンバーの公開鍵一覧を取得（ECDH共有用）。</summary>
    public IReadOnlyList<(string Username, string? PublicKey)> GetGroupMembersWithPublicKeys(
        string volumeName, string requesterUsername)
    {
        var header = LoadHeaderOrThrow(volumeName);
        if (header.OwnerUser != requesterUsername)
            throw new VolumeException("オーナーのみがメンバー情報を取得できます。");
        if (!header.IsE2ee)
            throw new VolumeException("E2EE ボリュームではありません。");

        // group__ プレフィックスからグループ名を抽出
        string groupName = volumeName.StartsWith("group__", StringComparison.Ordinal)
            ? volumeName[7..] : "";
        if (string.IsNullOrEmpty(groupName))
            throw new VolumeException("グループボリュームではありません。");

        var group = FindGroup(groupName)
            ?? throw new VolumeException($"グループ '{groupName}' が見つかりません。");

        return group.Members
            .Where(m => !header.HasUserAccess(m.Username))
            .Select(m => (m.Username, GetPublicKey(m.Username)))
            .ToList();
    }

    /// <summary>E2EEボリュームにECDHラップ済み鍵を一括追加。</summary>
    public void AddE2eeWrappedKeysBatch(string volumeName, string requesterUsername,
        Dictionary<string, VolumeHeader.UserWrappedKey> wrappedKeys)
    {
        _mountGate.Wait();
        try
        {
            var header = LoadHeaderOrThrow(volumeName);
            if (header.OwnerUser != requesterUsername)
                throw new VolumeException("オーナーのみが鍵を追加できます。");

            foreach (var (username, wrappedKey) in wrappedKeys)
            {
                if (!header.HasUserAccess(username))
                    header.AddWrappedKey(username, wrappedKey);
            }
            _metaStore.SaveAsync(volumeName, header).GetAwaiter().GetResult();
            RefreshMountedHeader(volumeName, header);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    // ---- ボリューム削除 ----

    public void DeleteVolume(string name)
    {
        _mountGate.Wait();
        try
        {
            if (_mounted.TryRemove(name, out var mv))
            {
                mv.Stream.Dispose();
                if (mv.MasterKey is not null) CryptographicOperations.ZeroMemory(mv.MasterKey);
            }
        }
        finally
        {
            _mountGate.Release();
        }

        // メタデータをストレージプロバイダ経由で削除
        try { _metaStore.DeleteAllAsync(name).GetAwaiter().GetResult(); } catch { }

        // ローカルの volume.dat を削除
        string dataPath = GetDataPath(name);
        if (File.Exists(dataPath))
            File.Delete(dataPath);

        // 空になったローカルディレクトリを掃除
        string dir = VolumeDir(name);
        if (Directory.Exists(dir) && !Directory.EnumerateFileSystemEntries(dir).Any())
            Directory.Delete(dir);
    }

    // ---- 内部 ----

    private void MountInternal(string name, VolumeHeader header, byte[]? masterKey)
    {
        // E2EE はサーバー側で暗号化しないため、FileStream を排他保持しない
        var share = header.IsE2ee ? FileShare.ReadWrite : FileShare.None;
        var fs = new FileStream(GetDataPath(name), FileMode.Open, FileAccess.ReadWrite, share);
        Stream stream = (header.Encrypted && masterKey is not null)
            ? new AesXtsStream(fs, masterKey, header.SectorSize, fs.Length, writable: true)
            : fs;
        _mounted[name] = new MountedVolume(header, masterKey, stream);
    }

    private VolumeHeader LoadHeaderOrThrow(string name)
    {
        return _metaStore.LoadAsync(name).GetAwaiter().GetResult()
            ?? throw new VolumeException($"ボリューム '{name}' が見つかりません。");
    }

    private VolumeHeader? LoadHeaderIfExists(string name)
        => _metaStore.LoadAsync(name).GetAwaiter().GetResult();

    private void RefreshMountedHeader(string name, VolumeHeader updated)
    {
        if (_mounted.TryGetValue(name, out var mv))
            mv.UpdateHeader(updated);
    }

    private static VolumeInfo ToInfo(string name, VolumeHeader h, bool mounted)
    {
        var wrapTypes = h.UserKeys.Count > 0
            ? h.UserKeys.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.WrapType, StringComparer.Ordinal)
            : null;
        return new(name, mounted, h.Encrypted, h.OwnerUser, h.CreatedAt,
            h.UserKeys.Keys.ToList(), h.EncryptionMode,
            h.AuthorizedGroups.ToList(),
            name.StartsWith("home__", StringComparison.Ordinal),
            wrapTypes);
    }

    private string VolumeDir(string name) => Path.Combine(_volumeDataPath, name);
    private string GetDataPath(string name) => Path.Combine(VolumeDir(name), "volume.dat");

    private HashSet<string> GetGroupsForUser(string username)
    {
        using var scope = _scopeFactory.CreateScope();
        var groupService = scope.ServiceProvider.GetRequiredService<GroupService>();
        return groupService.GetGroupsForUserAsync(username).GetAwaiter().GetResult()
            .Select(g => g.GroupName).ToHashSet(StringComparer.Ordinal);
    }

    private GroupEntity? FindGroup(string groupName)
    {
        using var scope = _scopeFactory.CreateScope();
        var groupService = scope.ServiceProvider.GetRequiredService<GroupService>();
        return groupService.FindAsync(groupName).GetAwaiter().GetResult();
    }

    private string? GetPublicKey(string username)
    {
        using var scope = _scopeFactory.CreateScope();
        var accountService = scope.ServiceProvider.GetRequiredService<AccountService>();
        return accountService.GetPublicKeyAsync(username).GetAwaiter().GetResult();
    }

    private static void ValidateName(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (name.StartsWith("home__", StringComparison.Ordinal))
            throw new VolumeException("'home__' で始まる名前は予約されています。");
        if (name.StartsWith("group__", StringComparison.Ordinal))
            throw new VolumeException("'group__' で始まる名前は予約されています。グループボリュームは別途作成してください。");
        if (name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new VolumeException("ボリューム名に使用できない文字が含まれています。");
        if (name.Length > 64)
            throw new VolumeException("ボリューム名は 64 文字以内にしてください。");
    }

    private sealed class MountedVolume(VolumeHeader header, byte[]? masterKey, Stream stream)
    {
        public VolumeHeader Header { get; private set; } = header;
        public byte[]? MasterKey { get; } = masterKey;
        public Stream Stream { get; } = stream;
        public void UpdateHeader(VolumeHeader h) => Header = h;
    }
}
