using CistaNAS.Web.Models;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;

namespace CistaNAS.Web.Services;

public sealed partial class VolumeService
{
    /// <summary>E2EE ボリュームを作成（クライアントから wrappedMasterKey を受け取る）。</summary>
    public Task<VolumeInfo> CreateE2eeAsync(string name, string username, VolumeHeader.UserWrappedKey wrappedKey, int chunkSize = 1048576)
    {
        ValidateName(name);
        ArgumentException.ThrowIfNullOrEmpty(username);

        return UnderMountGateAsync(async () =>
        {
            if (await _metaStore.ExistsAsync(name))
                throw new VolumeException($"ボリューム '{name}' は既に存在します。");

            var header = VolumeHeader.CreateE2ee(name, username, wrappedKey, chunkSize);

            Directory.CreateDirectory(VolumeDir(name));
            await _metaStore.SaveAsync(name, header);

            bool chunkMode = ShouldUseChunkMode();
            if (chunkMode)
                MountInternalChunked(name, header, masterKey: null);
            else
            {
                File.Create(GetDataPath(name)).Dispose();
                MountInternal(name, header, masterKey: null);
            }

            return ToInfo(name, header, true);
        });
    }

    /// <summary>E2EE ボリュームをマウント（アクセス権チェックのみ、鍵アンラップなし）。</summary>
    public Task<VolumeInfo> MountE2eeAsync(string name, string username)
    {
        return UnderMountGateAsync(async () =>
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

            // クラッシュ復旧: 未コミットジャーナルがあればカタログを修復してクリア
            await RecoverMountedVolumeAsync(name);

            return ToInfo(name, header, true);
        });
    }

    /// <summary>指定ユーザーの E2EE wrapped key を DTO で返す。ユーザーのエントリが無い場合は null。</summary>
    public async Task<WrappedKeyResponse?> GetWrappedKeyAsync(string volumeName, string username, CancellationToken ct = default)
    {
        var header = await LoadHeaderOrThrowAsync(volumeName);
        if (!header.UserKeys.TryGetValue(username, out var key))
            return null;

        return new WrappedKeyResponse(
            key.WrapType,
            new KdfResponse(key.Kdf.Algorithm, key.Kdf.Iterations, Convert.ToBase64String(key.Kdf.Salt)),
            new WrappedMasterKeyResponse(
                key.WrappedMasterKey.Algorithm,
                Convert.ToBase64String(key.WrappedMasterKey.Nonce),
                Convert.ToBase64String(key.WrappedMasterKey.Ciphertext),
                Convert.ToBase64String(key.WrappedMasterKey.Tag)),
            key.EphemeralPublicKey is not null ? Convert.ToBase64String(key.EphemeralPublicKey) : null,
            header.ChunkSize);
    }

    /// <summary>E2EE ボリュームに wrapped key を追加（クライアント側で再ラップ済み）。</summary>
    public Task AddE2eeWrappedKeyAsync(string volumeName, string granterUsername, string targetUsername, VolumeHeader.UserWrappedKey wrappedKey)
    {
        return UnderMountGateAsync(async () =>
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
        });
    }

    // ---- グループ E2EE ボリューム ----

    /// <summary>グループ専用E2EEボリュームを作成（group__ プレフィックス付き）。</summary>
    public Task<VolumeInfo> CreateGroupE2eeAsync(string groupName, string ownerUsername,
        VolumeHeader.UserWrappedKey ownerWrappedKey, int chunkSize = 1048576)
    {
        ArgumentException.ThrowIfNullOrEmpty(groupName);
        ArgumentException.ThrowIfNullOrEmpty(ownerUsername);

        return UnderMountGateAsync(async () =>
        {
            var group = await FindGroupAsync(groupName)
                ?? throw new VolumeException($"グループ '{groupName}' が見つかりません。");

            // グループボリュームの作成はグループオーナーのみ（メンバーによる勝手な作成を防ぐ）。
            if (group.OwnerUser != ownerUsername)
                throw new VolumeException("グループオーナーのみがグループボリュームを作成できます。");

            string volName = $"{VolumeHeader.GroupPrefix}{groupName}";
            if (await _metaStore.ExistsAsync(volName))
                throw new VolumeException($"グループボリューム '{volName}' は既に存在します。");

            var header = VolumeHeader.CreateE2ee(volName, ownerUsername, ownerWrappedKey, chunkSize);

            Directory.CreateDirectory(VolumeDir(volName));
            await _metaStore.SaveAsync(volName, header);

            bool chunkMode = ShouldUseChunkMode();
            if (chunkMode)
                MountInternalChunked(volName, header, masterKey: null);
            else
            {
                File.Create(GetDataPath(volName)).Dispose();
                MountInternal(volName, header, masterKey: null);
            }

            return ToInfo(volName, header, true);
        });
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
    public Task AddE2eeWrappedKeysBatchAsync(string volumeName, string requesterUsername,
        Dictionary<string, VolumeHeader.UserWrappedKey> wrappedKeys)
    {
        return UnderMountGateAsync(async () =>
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
        });
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
}
