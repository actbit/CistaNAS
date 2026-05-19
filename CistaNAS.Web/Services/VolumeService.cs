using System.Collections.Concurrent;
using System.Security.Cryptography;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Crypto;
using CistaNAS.Web.Models;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// ボリュームの作成・マウント・ロック・共有を管理する Singleton Service。
/// </summary>
public sealed class VolumeService
{
    private readonly string _dataRoot;
    private readonly VolumeOptions _volOpts;
    private readonly GroupStore _groupStore;

    private readonly ConcurrentDictionary<string, MountedVolume> _mounted = new();

    public VolumeService(IOptions<CistaNasOptions> options, GroupStore groupStore)
    {
        _dataRoot = options.Value.DataRoot;
        _volOpts = options.Value.Volume;
        _groupStore = groupStore;
        Directory.CreateDirectory(_dataRoot);
    }

    public VolumeInfo Create(string name, string? username, string? password, bool encrypted = true)
    {
        ValidateName(name);
        return CreateInternal(name, username, password, encrypted);
    }

    /// <summary>ホームボリューム等、内部用途の作成（home__ プレフィックスを許可）。</summary>
    public VolumeInfo CreateInternal(string name, string? username, string? password, bool encrypted = true)
    {
        if (encrypted) { ArgumentException.ThrowIfNullOrEmpty(username); ArgumentException.ThrowIfNullOrEmpty(password); }

        string dir = VolumeDir(name);
        if (Directory.Exists(dir))
            throw new VolumeException($"ボリューム '{name}' は既に存在します。");

        var (header, masterKey) = VolumeHeader.Create(name, username, password, _volOpts.SectorSize, _volOpts.KdfIterations, encrypted);

        Directory.CreateDirectory(dir);
        header.Save(Path.Combine(dir, VolumeHeader.FileName));
        File.Create(GetDataPath(name)).Dispose();
        MountInternal(name, header, masterKey);

        return ToInfo(name, header, true);
    }

    /// <summary>E2EE ボリュームを作成（クライアントから wrappedMasterKey を受け取る）。</summary>
    public VolumeInfo CreateE2ee(string name, string username, VolumeHeader.UserWrappedKey wrappedKey, int chunkSize = 1048576)
    {
        ValidateName(name);
        ArgumentException.ThrowIfNullOrEmpty(username);

        string dir = VolumeDir(name);
        if (Directory.Exists(dir))
            throw new VolumeException($"ボリューム '{name}' は既に存在します。");

        var header = VolumeHeader.CreateE2ee(name, username, wrappedKey, chunkSize);

        Directory.CreateDirectory(dir);
        header.Save(Path.Combine(dir, VolumeHeader.FileName));
        File.Create(GetDataPath(name)).Dispose();
        // E2EE: サーバーはマスターキーを持たない。raw FileStream でマウント。
        MountInternal(name, header, masterKey: null);

        return ToInfo(name, header, true);
    }

    public VolumeInfo Mount(string name, string username, string? password)
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

    /// <summary>E2EE ボリュームをマウント（アクセス権チェックのみ、鍵アンラップなし）。</summary>
    public VolumeInfo MountE2ee(string name, string username)
    {
        if (_mounted.ContainsKey(name))
            throw new VolumeException($"ボリューム '{name}' は既にマウントされています。");

        var header = LoadHeaderOrThrow(name);
        if (!header.IsE2ee)
            throw new VolumeException($"ボリューム '{name}' は E2EE ボリュームではありません。");
        if (!header.HasUserAccess(username))
            throw new VolumeException($"ユーザー '{username}' はこのボリュームにアクセス権がありません。");

        // E2EE: マスターキーなしで raw FileStream マウント
        MountInternal(name, header, masterKey: null);
        return ToInfo(name, header, true);
    }

    /// <summary>E2EE ボリュームに wrapped key を追加（クライアント側で再ラップ済み）。</summary>
    public void AddE2eeWrappedKey(string volumeName, string granterUsername, string targetUsername, VolumeHeader.UserWrappedKey wrappedKey)
    {
        var header = LoadHeaderOrThrow(volumeName);
        if (!header.IsE2ee)
            throw new VolumeException($"ボリューム '{volumeName}' は E2EE ボリュームではありません。");
        if (header.OwnerUser != granterUsername)
            throw new VolumeException("オーナーのみがアクセス権を付与できます。");
        if (!header.HasUserAccess(targetUsername))
            header.AddWrappedKey(targetUsername, wrappedKey);
        header.Save(GetHeaderPath(volumeName));
        RefreshMountedHeader(volumeName, header);
    }

    public void Lock(string name)
    {
        if (!_mounted.TryRemove(name, out var mv))
            throw new VolumeException($"ボリューム '{name}' はマウントされていません。");
        mv.Stream.Dispose();
        if (mv.MasterKey is not null) CryptographicOperations.ZeroMemory(mv.MasterKey);
    }

    /// <summary>指定ユーザーがアクセスできるボリューム一覧を返す。</summary>
    public IReadOnlyList<VolumeInfo> ListForUser(string username)
    {
        var result = new List<VolumeInfo>();
        if (!Directory.Exists(_dataRoot)) return result;

        var userGroups = _groupStore.GetGroupsForUser(username)
            .Select(g => g.GroupName).ToHashSet(StringComparer.Ordinal);

        foreach (var dir in Directory.EnumerateDirectories(_dataRoot))
        {
            string name = Path.GetFileName(dir);
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
        if (!Directory.Exists(_dataRoot)) return result;

        foreach (var dir in Directory.EnumerateDirectories(_dataRoot))
        {
            string name = Path.GetFileName(dir);
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
        var userGroups = _groupStore.GetGroupsForUser(username)
            .Select(g => g.GroupName).ToHashSet(StringComparer.Ordinal);
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

        var header = LoadHeaderOrThrow(volumeName);
        if (!header.HasUserAccess(granterUsername))
            throw new VolumeException($"ユーザー '{granterUsername}' はこのボリュームにアクセス権がありません。");

        byte[]? masterKey = header.UnwrapMasterKey(granterUsername, granterPassword)
            ?? throw new VolumeException("付与者の認証情報が正しくありません。");

        try
        {
            header.AddUserWrap(targetUsername, targetPassword, masterKey, _volOpts.KdfIterations);
            header.Save(GetHeaderPath(volumeName));
            RefreshMountedHeader(volumeName, header);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    /// <summary>ボリュームからユーザーのアクセス権を剥奪。</summary>
    public void RevokeAccess(string volumeName, string revokerUsername, string targetUsername)
    {
        var header = LoadHeaderOrThrow(volumeName);
        if (header.OwnerUser != revokerUsername)
            throw new VolumeException("オーナーのみがアクセス権を剥奪できます。");
        if (targetUsername == header.OwnerUser)
            throw new VolumeException("オーナーのアクセス権は剥奪できません。");

        header.RemoveUserWrap(targetUsername);
        header.Save(GetHeaderPath(volumeName));
        RefreshMountedHeader(volumeName, header);
    }

    /// <summary>ユーザーのパスワード変更時に全ボリュームの鍵を再ラップ。</summary>
    public void RewrapAllForUser(string username, string oldPassword, string newPassword)
    {
        if (!Directory.Exists(_dataRoot)) return;

        foreach (var dir in Directory.EnumerateDirectories(_dataRoot))
        {
            string name = Path.GetFileName(dir);
            var header = LoadHeaderIfExists(name);
            if (header is null || !header.HasUserAccess(username)) continue;

            header.RewrapUser(username, oldPassword, newPassword, _volOpts.KdfIterations);
            header.Save(GetHeaderPath(name));
            RefreshMountedHeader(name, header);
        }
    }

    // ---- グループアクセス ----

    public void GrantGroupAccess(string volumeName, string granterUsername, string groupName)
    {
        var header = LoadHeaderOrThrow(volumeName);
        if (header.OwnerUser != granterUsername)
            throw new VolumeException("オーナーのみがグループアクセスを付与できます。");
        if (header.IsE2ee)
            throw new VolumeException("E2EE ボリュームはグループ共有に対応していません。");
        if (_groupStore.Find(groupName) is null)
            throw new VolumeException($"グループ '{groupName}' が見つかりません。");

        header.AuthorizedGroups.Add(groupName);
        header.Save(GetHeaderPath(volumeName));
        RefreshMountedHeader(volumeName, header);
    }

    public void RevokeGroupAccess(string volumeName, string revokerUsername, string groupName)
    {
        var header = LoadHeaderOrThrow(volumeName);
        if (header.OwnerUser != revokerUsername)
            throw new VolumeException("オーナーのみがグループアクセスを剥奪できます。");
        if (!header.AuthorizedGroups.Remove(groupName))
            throw new VolumeException($"グループ '{groupName}' はこのボリュームにアクセス権がありません。");

        header.Save(GetHeaderPath(volumeName));
        RefreshMountedHeader(volumeName, header);
    }

    public void RemoveGroupFromAllVolumes(string groupName)
    {
        if (!Directory.Exists(_dataRoot)) return;
        foreach (var dir in Directory.EnumerateDirectories(_dataRoot))
        {
            string name = Path.GetFileName(dir);
            var header = LoadHeaderIfExists(name);
            if (header is null) continue;
            if (header.AuthorizedGroups.Remove(groupName))
            {
                header.Save(GetHeaderPath(name));
                RefreshMountedHeader(name, header);
            }
        }
    }

    // ---- ボリューム削除 ----

    public void DeleteVolume(string name)
    {
        if (_mounted.TryRemove(name, out var mv))
        {
            mv.Stream.Dispose();
            if (mv.MasterKey is not null) CryptographicOperations.ZeroMemory(mv.MasterKey);
        }

        string dir = VolumeDir(name);
        if (Directory.Exists(dir))
            Directory.Delete(dir, recursive: true);
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
        string path = GetHeaderPath(name);
        if (!File.Exists(path))
            throw new VolumeException($"ボリューム '{name}' が見つかりません。");
        return VolumeHeader.Load(path);
    }

    private VolumeHeader? LoadHeaderIfExists(string name)
    {
        string path = GetHeaderPath(name);
        if (!File.Exists(path)) return null;
        return VolumeHeader.Load(path);
    }

    private void RefreshMountedHeader(string name, VolumeHeader updated)
    {
        if (_mounted.TryGetValue(name, out var mv))
            mv.UpdateHeader(updated);
    }

    private static VolumeInfo ToInfo(string name, VolumeHeader h, bool mounted) => new(
        name, mounted, h.Encrypted, h.OwnerUser, h.CreatedAt,
        h.UserKeys.Keys.ToList(), h.EncryptionMode,
        h.AuthorizedGroups.ToList(),
        name.StartsWith("home__", StringComparison.Ordinal));

    private string VolumeDir(string name) => Path.Combine(_dataRoot, name);
    private string GetDataPath(string name) => Path.Combine(VolumeDir(name), "volume.dat");
    private string GetHeaderPath(string name) => Path.Combine(VolumeDir(name), VolumeHeader.FileName);

    private static void ValidateName(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (name.StartsWith("home__", StringComparison.Ordinal))
            throw new VolumeException("'home__' で始まる名前は予約されています。");
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
