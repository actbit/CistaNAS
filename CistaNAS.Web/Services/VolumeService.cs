using System.Collections.Concurrent;
using System.Security.Cryptography;
using CistaNAS.Web.Configuration;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Identity;
using CistaNAS.Web.Models;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// ボリュームの作成・マウント・ロック・共有を管理する Singleton Service。
/// メタデータは VolumeMetadataStore（IStorageProvider）経由で保存し、
/// volume.dat はローカルファイルシステムに配置。
/// </summary>
public sealed class VolumeService : IDisposable
{
    private int _disposed;
    private readonly string _volumeDataPath;
    private readonly VolumeOptions _volOpts;
    private readonly string _storageProvider;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly VolumeMetadataStore _metaStore;
    private readonly IChunkStore _chunkStore;
    private readonly ILogger<VolumeService> _logger;

    private readonly ConcurrentDictionary<string, MountedVolume> _mounted = new();
    private readonly SemaphoreSlim _mountGate = new(1, 1);

    public VolumeService(
        IOptions<CistaNasOptions> options,
        IServiceScopeFactory scopeFactory,
        VolumeMetadataStore metaStore,
        IChunkStore chunkStore,
        ILogger<VolumeService> logger)
    {
        _volumeDataPath = options.Value.Storage.VolumeDataPath ?? options.Value.DataRoot;
        _volOpts = options.Value.Volume;
        _storageProvider = options.Value.Storage.Provider.ToLowerInvariant();
        _scopeFactory = scopeFactory;
        _metaStore = metaStore;
        _chunkStore = chunkStore;
        _logger = logger;
        Directory.CreateDirectory(_volumeDataPath);
    }

    /// <summary>"auto" 設定時に、S3 プロバイダ使用中ならチャンクモードにするかを判定。</summary>
    private bool ShouldUseChunkMode() =>
        _volOpts.ChunkStorage == "auto" && _storageProvider != "local";

    public async Task<VolumeInfo> CreateAsync(string name, string? username, string? password, bool encrypted = true)
    {
        ValidateName(name);
        // CreateInternalAsync 内部で _mountGate を取得するため、ここでは取得しない
        return await CreateInternalAsync(name, username, password, encrypted);
    }

    /// <summary>ホームボリューム等、内部用途の作成（home__ プレフィックスを許可）。</summary>
    public async Task<VolumeInfo> CreateInternalAsync(string name, string? username, string? password, bool encrypted = true)
    {
        // 内部呼び出し（CreateUserAsync 等）では ValidateName をスキップ。
        // home__ / group__ プレフィックスや長さ制限を許可する。
        // CreateAsync 経由の場合は事前に ValidateName が呼ばれている。
        await _mountGate.WaitAsync();
        try
        {
        // ユーザー設定を取得して暗号化モードとアルゴリズムを決定
        string cipherAlgorithm = "aes-256-xts";  // デフォルト
        bool shouldEncrypt = encrypted;

        if (encrypted && !string.IsNullOrEmpty(username))
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByNameAsync(username);
            if (user is not null)
            {
                // ユーザーのデフォルト設定を使用
                if (!string.IsNullOrEmpty(user.DefaultEncryptionMode))
                {
                    shouldEncrypt = user.DefaultEncryptionMode != "server";
                }
                if (!string.IsNullOrEmpty(user.DefaultCipherAlgorithm))
                {
                    cipherAlgorithm = user.DefaultCipherAlgorithm;
                }
            }
        }

        if (shouldEncrypt) { ArgumentException.ThrowIfNullOrEmpty(username); ArgumentException.ThrowIfNullOrEmpty(password); }

        if (await _metaStore.ExistsAsync(name))
            throw new VolumeException($"ボリューム '{name}' は既に存在します。");

        var (header, masterKey) = VolumeHeader.Create(name, username, password, _volOpts.SectorSize, _volOpts.KdfIterations, shouldEncrypt, cipherAlgorithm);

        // チャンクモード判定: "auto" かつ S3 プロバイダ使用時
        bool chunkMode = ShouldUseChunkMode();
        if (chunkMode)
        {
            header.StorageMode = "chunk";
            header.ServerChunkSize = _volOpts.ServerChunkSize;
        }

        Directory.CreateDirectory(VolumeDir(name));
        await _metaStore.SaveAsync(name, header);

        if (chunkMode)
        {
            // チャンクモード: volume.dat は作成しない
            MountInternalChunked(name, header, masterKey);
        }
        else
        {
            File.Create(GetDataPath(name)).Dispose();
            MountInternal(name, header, masterKey);
        }

        return ToInfo(name, header, true);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    /// <summary>E2EE ボリュームを作成（クライアントから wrappedMasterKey を受け取る）。</summary>
    public async Task<VolumeInfo> CreateE2eeAsync(string name, string username, VolumeHeader.UserWrappedKey wrappedKey, int chunkSize = 1048576)
    {
        ValidateName(name);
        ArgumentException.ThrowIfNullOrEmpty(username);

        await _mountGate.WaitAsync();
        try
        {
            if (await _metaStore.ExistsAsync(name))
                throw new VolumeException($"ボリューム '{name}' は既に存在します。");

            var header = VolumeHeader.CreateE2ee(name, username, wrappedKey, chunkSize);

            Directory.CreateDirectory(VolumeDir(name));
            await _metaStore.SaveAsync(name, header);
            File.Create(GetDataPath(name)).Dispose();
            MountInternal(name, header, masterKey: null);

            return ToInfo(name, header, true);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    public async Task<VolumeInfo> MountAsync(string name, string username, string? password)
    {
        await _mountGate.WaitAsync();
        try
        {
            if (_mounted.ContainsKey(name))
                throw new VolumeException($"ボリューム '{name}' は既にマウントされています。");

            var header = await LoadHeaderOrThrowAsync(name);
            byte[]? masterKey = null;
            if (header.Encrypted)
            {
                ArgumentException.ThrowIfNullOrEmpty(username);
                ArgumentException.ThrowIfNullOrEmpty(password);
                masterKey = header.UnwrapMasterKey(username, password)
                    ?? throw new VolumeException("認証情報が正しくありません。");
            }

            if (header.StorageMode == "chunk")
                MountInternalChunked(name, header, masterKey);
            else
                MountInternal(name, header, masterKey);
            return ToInfo(name, header, true);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    /// <summary>E2EE ボリュームをマウント（アクセス権チェックのみ、鍵アンラップなし）。</summary>
    public async Task<VolumeInfo> MountE2eeAsync(string name, string username)
    {
        await _mountGate.WaitAsync();
        try
        {
            if (_mounted.ContainsKey(name))
                throw new VolumeException($"ボリューム '{name}' は既にマウントされています。");

            var header = await LoadHeaderOrThrowAsync(name);
            if (!header.IsE2ee)
                throw new VolumeException($"ボリューム '{name}' は E2EE ボリュームではありません。");
            if (!header.HasUserAccess(username))
                throw new VolumeException($"ユーザー '{username}' はこのボリュームにアクセス権がありません。");

            if (header.StorageMode == "chunk")
                MountInternalChunked(name, header, masterKey: null);
            else
                MountInternal(name, header, masterKey: null);
            return ToInfo(name, header, true);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    /// <summary>E2EE ボリュームに wrapped key を追加（クライアント側で再ラップ済み）。</summary>
    public async Task AddE2eeWrappedKeyAsync(string volumeName, string granterUsername, string targetUsername, VolumeHeader.UserWrappedKey wrappedKey)
    {
        await _mountGate.WaitAsync();
        try
        {
            var header = await LoadHeaderOrThrowAsync(volumeName);
            if (!header.IsE2ee)
                throw new VolumeException($"ボリューム '{volumeName}' は E2EE ボリュームではありません。");
            if (header.OwnerUser != granterUsername)
                throw new VolumeException("オーナーのみがアクセス権を付与できます。");
            if (!header.HasUserAccess(targetUsername))
                header.AddWrappedKey(targetUsername, wrappedKey);
            await _metaStore.SaveAsync(volumeName, header);
            RefreshMountedHeader(volumeName, header);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    /// <summary>ボリュームをロック（アンマウント）する。オーナーのみ実行可能。</summary>
    public async Task LockAsync(string name, string username)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);

        await _mountGate.WaitAsync();
        try
        {
            if (!_mounted.TryGetValue(name, out var mv))
                throw new VolumeException($"ボリューム '{name}' はマウントされていません。");

            if (mv.Header.OwnerUser != username)
                throw new VolumeException("オーナーのみがボリュームをロックできます。");

            _mounted.TryRemove(name, out _);
            mv.Stream.Dispose();
            if (mv.MasterKey is not null) CryptographicOperations.ZeroMemory(mv.MasterKey);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    /// <summary>ボリューム情報を返す。存在しない場合は null。</summary>
    public async Task<VolumeInfo?> GetVolumeInfoAsync(string name)
    {
        var header = await LoadHeaderIfExistsAsync(name);
        if (header is null) return null;
        return ToInfo(name, header, _mounted.ContainsKey(name));
    }

    /// <summary>ボリュームヘッダを返す。存在しない場合は例外。</summary>
    public async Task<VolumeHeader> GetVolumeHeaderAsync(string name) => await LoadHeaderOrThrowAsync(name);

    /// <summary>指定ユーザーがアクセスできるボリューム一覧を返す。</summary>
    public async Task<IReadOnlyList<VolumeInfo>> ListForUserAsync(string username)
    {
        var result = new List<VolumeInfo>();
        var volumeNames = await _metaStore.ListVolumeNamesAsync();

        var userGroups = await GetGroupsForUserAsync(username);

        foreach (var name in volumeNames)
        {
            var header = await LoadHeaderIfExistsAsync(name);
            if (header is null) continue;

            if (!HasAccessInternal(header, username, userGroups)) continue;

            result.Add(ToInfo(name, header, _mounted.ContainsKey(name)));
        }
        return result;
    }

    public async Task<IReadOnlyList<VolumeInfo>> ListAllAsync()
    {
        var result = new List<VolumeInfo>();
        var volumeNames = await _metaStore.ListVolumeNamesAsync();

        foreach (var name in volumeNames)
        {
            var header = await LoadHeaderIfExistsAsync(name);
            if (header is null) continue;
            result.Add(ToInfo(name, header, _mounted.ContainsKey(name)));
        }
        return result;
    }

    public (Stream Stream, VolumeHeader Header) GetMounted(string name)
    {
        if (!_mounted.TryGetValue(name, out var mv))
            throw new VolumeException($"ボリューム '{name}' はマウントされていません。");
        // スナップショットを返す: LockAsync で mv.Stream が Dispose されても
        // 呼び出し側が使用中のストリームは安全に動作する。
        return (mv.Stream, mv.Header);
    }

    /// <summary>マウント済みボリュームの Header と MasterKey を取得（Stream は不要なケース用）。</summary>
    public (VolumeHeader Header, byte[]? MasterKey) GetMountedKeys(string name)
    {
        if (!_mounted.TryGetValue(name, out var mv))
            throw new VolumeException($"ボリューム '{name}' はマウントされていません。");
        return (mv.Header, mv.MasterKey);
    }

    public bool IsMounted(string name) => _mounted.ContainsKey(name);

    /// <summary>ボリュームが指定ユーザーのアクセス権を持つか。</summary>
    public async Task<bool> HasAccessAsync(string volumeName, string username)
    {
        var header = await LoadHeaderIfExistsAsync(volumeName);
        if (header is null) return false;
        var userGroups = await GetGroupsForUserAsync(username);
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
    public async Task GrantAccessAsync(string volumeName, string granterUsername, string granterPassword,
        string targetUsername, string targetPassword)
    {
        ArgumentException.ThrowIfNullOrEmpty(granterUsername);
        ArgumentException.ThrowIfNullOrEmpty(granterPassword);
        ArgumentException.ThrowIfNullOrEmpty(targetUsername);
        ArgumentException.ThrowIfNullOrEmpty(targetPassword);

        await _mountGate.WaitAsync();
        try
        {
            var header = await LoadHeaderOrThrowAsync(volumeName);
            if (header.OwnerUser != granterUsername)
                throw new VolumeException("オーナーのみがアクセス権を付与できます。");

            byte[]? masterKey = header.UnwrapMasterKey(granterUsername, granterPassword)
                ?? throw new VolumeException("付与者の認証情報が正しくありません。");

            try
            {
                header.AddUserWrap(targetUsername, targetPassword, masterKey, _volOpts.KdfIterations);
                await _metaStore.SaveAsync(volumeName, header);
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
    public async Task RevokeAccessAsync(string volumeName, string revokerUsername, string targetUsername)
    {
        await _mountGate.WaitAsync();
        try
        {
            var header = await LoadHeaderOrThrowAsync(volumeName);
            if (header.OwnerUser != revokerUsername)
                throw new VolumeException("オーナーのみがアクセス権を剥奪できます。");
            if (targetUsername == header.OwnerUser)
                throw new VolumeException("オーナーのアクセス権は剥奪できません。");

            header.RemoveUserWrap(targetUsername);
            await _metaStore.SaveAsync(volumeName, header);
            RefreshMountedHeader(volumeName, header);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    /// <summary>ユーザーのパスワード変更時に全ボリュームの鍵を再ラップ。</summary>
    public async Task RewrapAllForUserAsync(string username, string oldPassword, string newPassword)
    {
        var volumeNames = await _metaStore.ListVolumeNamesAsync();

        await _mountGate.WaitAsync();
        try
        {
            foreach (var name in volumeNames)
            {
                var header = await LoadHeaderIfExistsAsync(name);
                if (header is null || !header.HasUserAccess(username)) continue;

                header.RewrapUser(username, oldPassword, newPassword, _volOpts.KdfIterations);
                await _metaStore.SaveAsync(name, header);
                RefreshMountedHeader(name, header);
            }
        }
        finally
        {
            _mountGate.Release();
        }
    }

    // ---- グループアクセス ----

    public async Task GrantGroupAccessAsync(string volumeName, string granterUsername, string groupName)
    {
        await _mountGate.WaitAsync();
        try
        {
            var header = await LoadHeaderOrThrowAsync(volumeName);
            if (header.OwnerUser != granterUsername)
                throw new VolumeException("オーナーのみがグループアクセスを付与できます。");
            if (header.IsE2ee)
                throw new VolumeException("E2EE ボリュームはグループ共有に対応していません。");
            if (await FindGroupAsync(groupName) is null)
                throw new VolumeException($"グループ '{groupName}' が見つかりません。");

            header.AuthorizedGroups.Add(groupName);
            await _metaStore.SaveAsync(volumeName, header);
            RefreshMountedHeader(volumeName, header);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    public async Task RevokeGroupAccessAsync(string volumeName, string revokerUsername, string groupName)
    {
        await _mountGate.WaitAsync();
        try
        {
            var header = await LoadHeaderOrThrowAsync(volumeName);
            if (header.OwnerUser != revokerUsername)
                throw new VolumeException("オーナーのみがグループアクセスを剥奪できます。");
            if (!header.AuthorizedGroups.Remove(groupName))
                throw new VolumeException($"グループ '{groupName}' はこのボリュームにアクセス権がありません。");

            await _metaStore.SaveAsync(volumeName, header);
            RefreshMountedHeader(volumeName, header);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    public async Task RemoveGroupFromAllVolumesAsync(string groupName)
    {
        var volumeNames = await _metaStore.ListVolumeNamesAsync();

        await _mountGate.WaitAsync();
        try
        {
            foreach (var name in volumeNames)
            {
                var header = await LoadHeaderIfExistsAsync(name);
                if (header is null) continue;
                if (header.AuthorizedGroups.Remove(groupName))
                {
                    await _metaStore.SaveAsync(name, header);
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
    public async Task<VolumeInfo> CreateGroupE2eeAsync(string groupName, string ownerUsername,
        VolumeHeader.UserWrappedKey ownerWrappedKey, int chunkSize = 1048576)
    {
        ArgumentException.ThrowIfNullOrEmpty(groupName);
        ArgumentException.ThrowIfNullOrEmpty(ownerUsername);

        await _mountGate.WaitAsync();
        try
        {
            var group = await FindGroupAsync(groupName)
                ?? throw new VolumeException($"グループ '{groupName}' が見つかりません。");

            if (!group.Members.Any(m => string.Equals(m.Username, ownerUsername, StringComparison.Ordinal)))
                throw new VolumeException($"ユーザー '{ownerUsername}' はグループ '{groupName}' のメンバーではありません。");

            string volName = $"{VolumeHeader.GroupPrefix}{groupName}";
            if (await _metaStore.ExistsAsync(volName))
                throw new VolumeException($"グループボリューム '{volName}' は既に存在します。");

            var header = VolumeHeader.CreateE2ee(volName, ownerUsername, ownerWrappedKey, chunkSize);

            Directory.CreateDirectory(VolumeDir(volName));
            await _metaStore.SaveAsync(volName, header);
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
    public async Task<IReadOnlyList<VolumeInfo>> GetGroupE2eeVolumesAsync(string groupName)
    {
        var result = new List<VolumeInfo>();
        string prefix = $"{VolumeHeader.GroupPrefix}{groupName}";
        var volumeNames = await _metaStore.ListVolumeNamesAsync();

        foreach (var name in volumeNames)
        {
            if (name != prefix) continue;
            var header = await LoadHeaderIfExistsAsync(name);
            if (header is null || !header.IsE2ee) continue;
            result.Add(ToInfo(name, header, _mounted.ContainsKey(name)));
        }
        return result;
    }

    /// <summary>グループメンバーの公開鍵一覧を取得（ECDH共有用）。</summary>
    public async Task<IReadOnlyList<(string Username, string? PublicKey)>> GetGroupMembersWithPublicKeysAsync(
        string volumeName, string requesterUsername)
    {
        var header = await LoadHeaderOrThrowAsync(volumeName);
        if (header.OwnerUser != requesterUsername)
            throw new VolumeException("オーナーのみがメンバー情報を取得できます。");
        if (!header.IsE2ee)
            throw new VolumeException("E2EE ボリュームではありません。");

        // group__ プレフィックスからグループ名を抽出
        string groupName = volumeName.StartsWith(VolumeHeader.GroupPrefix, StringComparison.Ordinal)
            ? volumeName[7..] : "";
        if (string.IsNullOrEmpty(groupName))
            throw new VolumeException("グループボリュームではありません。");

        var group = await FindGroupAsync(groupName)
            ?? throw new VolumeException($"グループ '{groupName}' が見つかりません。");

        var members = await GetGroupMembersWithPublicKeysAsync(group.Members
            .Where(m => !header.HasUserAccess(m.Username))
            .Select(m => m.Username)
            .ToList());
        return members;
    }

    /// <summary>E2EEボリュームにECDHラップ済み鍵を一括追加。</summary>
    public async Task AddE2eeWrappedKeysBatchAsync(string volumeName, string requesterUsername,
        Dictionary<string, VolumeHeader.UserWrappedKey> wrappedKeys)
    {
        await _mountGate.WaitAsync();
        try
        {
            var header = await LoadHeaderOrThrowAsync(volumeName);
            if (header.OwnerUser != requesterUsername)
                throw new VolumeException("オーナーのみが鍵を追加できます。");

            foreach (var (username, wrappedKey) in wrappedKeys)
            {
                if (!header.HasUserAccess(username))
                    header.AddWrappedKey(username, wrappedKey);
            }
            await _metaStore.SaveAsync(volumeName, header);
            RefreshMountedHeader(volumeName, header);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    // ---- ユーザークオータ ----

    /// <summary>ユーザーのクオータを設定する（ボリュームオーナーのみ）。</summary>
    public async Task SetUserQuotaAsync(string volumeName, string targetUsername, long maxBytes)
    {
        // _mountGate で並行 MountAsync / ヘッダ更新との競合を防ぐ (H-4)
        await _mountGate.WaitAsync();
        try
        {
            var header = await LoadHeaderOrThrowAsync(volumeName);
            header.UserQuotas[targetUsername] = maxBytes;
            await _metaStore.SaveAsync(volumeName, header);

            // マウント済みの場合、RefreshMountedHeader で全体を置換して
            // 他のスレッドからの読み取りとの競合を防ぐ
            RefreshMountedHeader(volumeName, header);
        }
        finally
        {
            _mountGate.Release();
        }
    }

    // ---- ボリューム削除 ----

    /// <summary>ボリュームを削除する。username が非 null の場合はオーナーまたは admin のみ実行可能。</summary>
    public async Task DeleteVolumeAsync(string name, string? username = null, bool isAdmin = false)
    {
        await _mountGate.WaitAsync();
        try
        {
            // 認可: username が指定されている場合はオーナーまたは admin に限定
            if (username is not null && !isAdmin)
            {
                var header = await LoadHeaderOrThrowAsync(name);
                if (header.OwnerUser != username)
                    throw new VolumeException("オーナーのみがボリュームを削除できます。");
            }
            if (_mounted.TryRemove(name, out var mv))
            {
                mv.Stream.Dispose();
                if (mv.MasterKey is not null) CryptographicOperations.ZeroMemory(mv.MasterKey);
            }

            // メタデータとローカルファイルの削除をマウントゲート内で実行
            // （アンマウントと削除の間に別リクエストが介入するのを防止）

            // メタデータをストレージプロバイダ経由で削除
            try { await _metaStore.DeleteAllAsync(name); }
            catch (Exception ex) { _logger.LogWarning(ex, "ボリューム '{Volume}' のメタデータ削除に失敗しました。", name); }

            // ロックを解除（ボリューム削除後は不要）
            try { _metaStore.Storage.RemoveLock(name); }
            catch (Exception ex) { _logger.LogWarning(ex, "ボリューム '{Volume}' のロック解除に失敗しました。", name); }

            // ローカルの volume.dat を削除
            string dataPath = GetDataPath(name);
            if (File.Exists(dataPath))
                File.Delete(dataPath);

            // チャンクモード: S3 からボリューム配下の全チャンクを削除
            try { await _chunkStore.DeleteVolumeChunksAsync(name); }
            catch (Exception ex) { _logger.LogWarning(ex, "ボリューム '{Volume}' のチャンク削除に失敗しました。", name); }

            // 空になったローカルディレクトリを掃除
            string dir = VolumeDir(name);
            if (Directory.Exists(dir) && !Directory.EnumerateFileSystemEntries(dir).Any())
                Directory.Delete(dir);

            // ストリームロック・カタログロック・E2EEファイルゲートを解放
            try
            {
                await using var scope = _scopeFactory.CreateAsyncScope();
                var fileService = scope.ServiceProvider.GetRequiredService<FileService>();
                FileService.RemoveStreamLock(name);
                FileService.RemoveCatalogLock(name);

                var e2eeFs = scope.ServiceProvider.GetRequiredService<E2eeFileService>();
                e2eeFs.CleanupVolumeGates(name);
            }
            catch (Exception ex) { _logger.LogWarning(ex, "ボリューム '{Volume}' のリソース解放に失敗しました。", name); }
        }
        finally
        {
            _mountGate.Release();
        }
    }

    // ---- 内部 ----

    private void MountInternal(string name, VolumeHeader header, byte[]? masterKey)
    {
        // E2EEはサーバー側で暗号化しないため、FileStream を排他保持しない
        var share = header.IsE2ee ? FileShare.ReadWrite : FileShare.None;
        var fs = new FileStream(GetDataPath(name), FileMode.Open, FileAccess.ReadWrite, share, 4096, FileOptions.Asynchronous);
        Stream stream = (header.Encrypted && masterKey is not null)
            ? new AesXtsStream(fs, masterKey, header.SectorSize, fs.Length, writable: true)
            : fs;
        _mounted[name] = new MountedVolume(header, masterKey, stream);
    }

    /// <summary>チャンクモード: FileStream を開かずにマウント。データは IChunkStore 経由でアクセス。</summary>
    private void MountInternalChunked(string name, VolumeHeader header, byte[]? masterKey)
    {
        // チャンクモードでは FileStream を持たない。ダミーの空ストリームを設定。
        // GetMounted() はチャンクモードでは呼ばれない前提（GetMountedKeys を使用）。
        _mounted[name] = new MountedVolume(header, masterKey, Stream.Null);
    }

    private async Task<VolumeHeader> LoadHeaderOrThrowAsync(string name)
    {
        return (await _metaStore.LoadAsync(name))
            ?? throw new VolumeException($"ボリューム '{name}' が見つかりません。");
    }

    private async Task<VolumeHeader?> LoadHeaderIfExistsAsync(string name)
        => await _metaStore.LoadAsync(name);

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
            h.CipherAlgorithm, h.KeySize,
            h.AuthorizedGroups.ToList(),
            name.StartsWith(VolumeHeader.HomePrefix, StringComparison.Ordinal),
            wrapTypes);
    }

    private string VolumeDir(string name) => Path.Combine(_volumeDataPath, name);
    private string GetDataPath(string name) => Path.Combine(VolumeDir(name), "volume.dat");

    private async Task<HashSet<string>> GetGroupsForUserAsync(string username)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var groupService = scope.ServiceProvider.GetRequiredService<GroupService>();
        var groups = await groupService.GetGroupsForUserAsync(username);
        return groups.Select(g => g.GroupName).ToHashSet(StringComparer.Ordinal);
    }

    private async Task<GroupEntity?> FindGroupAsync(string groupName)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var groupService = scope.ServiceProvider.GetRequiredService<GroupService>();
        return await groupService.FindAsync(groupName);
    }

    private async Task<IReadOnlyList<(string Username, string? PublicKey)>> GetGroupMembersWithPublicKeysAsync(
        List<string> usernames)
    {
        var results = new List<(string Username, string? PublicKey)>(usernames.Count);
        await using var scope = _scopeFactory.CreateAsyncScope();
        var accountService = scope.ServiceProvider.GetRequiredService<AccountService>();
        foreach (var username in usernames)
        {
            var pubKey = await accountService.GetPublicKeyAsync(username);
            results.Add((username, pubKey));
        }
        return results;
    }

    private static void ValidateName(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (name.StartsWith(VolumeHeader.HomePrefix, StringComparison.Ordinal))
            throw new VolumeException("'home__' で始まる名前は予約されています。");
        if (name.StartsWith(VolumeHeader.GroupPrefix, StringComparison.Ordinal))
            throw new VolumeException("'group__' で始まる名前は予約されています。グループボリュームは別途作成してください。");
        if (name.Length > 64)
            throw new VolumeException("ボリューム名は 64 文字以内にしてください。");
        foreach (char c in name)
        {
            if (!char.IsLetterOrDigit(c) && c != '-' && c != '_' && c != '.')
                throw new VolumeException("ボリューム名に使用できない文字が含まれています。");
        }
        if (name == "." || name == "..")
            throw new VolumeException("ボリューム名に使用できない文字が含まれています。");
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;

        foreach (var kvp in _mounted)
        {
            kvp.Value.Stream.Dispose();
            if (kvp.Value.MasterKey is not null)
                CryptographicOperations.ZeroMemory(kvp.Value.MasterKey);
        }
        _mounted.Clear();
        _mountGate.Dispose();
    }

    private sealed class MountedVolume(VolumeHeader header, byte[]? masterKey, Stream stream)
    {
        private volatile VolumeHeader _header = header;
        public VolumeHeader Header { get => _header; private set => _header = value; }
        public byte[]? MasterKey { get; } = masterKey;
        public Stream Stream { get; } = stream;
        public void UpdateHeader(VolumeHeader h) => Header = h;
    }
}
