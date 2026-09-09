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
            new KdfResponse(
                key.Kdf.Algorithm,
                key.Kdf.Iterations,
                key.Kdf.MemoryKiB,
                key.Kdf.Parallelism,
                key.Kdf.TimeCost,
                Convert.ToBase64String(key.Kdf.Salt)),
            new WrappedMasterKeyResponse(
                key.WrappedMasterKey.Algorithm,
                Convert.ToBase64String(key.WrappedMasterKey.Nonce),
                Convert.ToBase64String(key.WrappedMasterKey.Ciphertext),
                Convert.ToBase64String(key.WrappedMasterKey.Tag)),
            key.EphemeralPublicKey is not null ? Convert.ToBase64String(key.EphemeralPublicKey) : null,
            header.ChunkSize);
    }

    /// <summary>
    /// E2EE ボリュームに wrapped key を追加（クライアント側で再ラップ済み）。
    /// crypto format v2 ボリューム（KeyEpoch ≥ 1）では、この wrap は現行 epoch の GroupKey
    /// wrap として登録される（追加メンバーは現行 epoch 以降のデータのみ読める）。
    /// </summary>
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
            if (header.KeyEpoch >= 1)
                header.AddGroupKeyWrap(header.KeyEpoch, targetUsername, wrappedKey);
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

    /// <summary>E2EEボリュームにECDHラップ済み鍵を一括追加。v2 ボリュームでは現行 epoch の GroupKey wrap として登録。</summary>
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
                if (header.KeyEpoch >= 1)
                    header.AddGroupKeyWrap(header.KeyEpoch, username, wrappedKey);
            }
            await _metaStore.SaveAsync(volumeName, header);
            RefreshMountedHeader(volumeName, header);
        });
    }

    // ---- 共有 v2: GroupKey epoch ----

    /// <summary>
    /// crypto format v2: GroupKey をローテーションする（revoke によるメンバー縮小時）。
    /// クライアント（オーナー）が新 GroupKey K_n+1 を remaining members の公開鍵で ECDH ラップして送る。
    /// サーバーは epoch の連続性（n+1 のみ許可）と、削除対象ユーザーへの wrap が含まれないことを検証し、
    /// epoch 登録 + 剥奪ユーザーの全 wraps / UserKeys 削除を原子的に適用する。
    /// 旧 epoch の wraps は remaining members が旧ファイルを読むために保持する。
    /// </summary>
    public Task RotateGroupKeyAsync(string volumeName, string requesterUsername, E2eeRotateGroupKeyRequest request)
    {
        ArgumentException.ThrowIfNullOrEmpty(requesterUsername);

        return UnderMountGateAsync(async () =>
        {
            var header = await LoadHeaderOrThrowAsync(volumeName);
            if (!header.IsE2ee)
                throw new VolumeException($"ボリューム '{volumeName}' は E2EE ボリュームではありません。");
            if (header.OwnerUser != requesterUsername)
                throw new VolumeException("オーナーのみが GroupKey をローテーションできます。");

            // epoch は厳密に +1（巻き戻し・スキップ防止）
            if (request.NewEpoch != header.KeyEpoch + 1)
                throw new VolumeException($"NewEpoch は {header.KeyEpoch + 1} である必要があります（現在: {header.KeyEpoch}）。");
            if (request.WrappedGroupKeys.Count == 0)
                throw new VolumeException("WrappedGroupKeys が空です（remaining members 宛ての wrap が必要です）。");

            // 剥奪対象に新しい GroupKey をラップしてはならない（revoke の基本要件）
            if (request.RemovedUsername is not null
                && request.WrappedGroupKeys.ContainsKey(request.RemovedUsername))
                throw new VolumeException($"削除対象ユーザー '{request.RemovedUsername}' に新しい GroupKey をラップすることはできません。");

            // wrap 先は実在ユーザーかつ remaining members（剥奪対象以外）
            foreach (var username in request.WrappedGroupKeys.Keys)
            {
                if (username == request.RemovedUsername)
                    throw new VolumeException($"削除対象ユーザー '{username}' に新しい GroupKey をラップすることはできません。");
                if (!header.HasUserAccess(username))
                    throw new VolumeException($"ユーザー '{username}' はこのボリュームのメンバーではありません（先に add-wrapped-key で鍵を登録してください）。");
            }

            // 剥奪対象はオーナー以外のメンバーであること
            if (request.RemovedUsername is not null)
            {
                if (request.RemovedUsername == header.OwnerUser)
                    throw new VolumeException("オーナーのアクセス権は剥奪できません。");
                if (!header.HasUserAccess(request.RemovedUsername))
                    throw new VolumeException($"ユーザー '{request.RemovedUsername}' はこのボリュームのメンバーではありません。");
            }

            header.EnsureVolumeId();
            header.AddGroupEpoch(request.NewEpoch, request.WrappedGroupKeys);

            if (request.RemovedUsername is not null)
                header.RemoveUserEverywhere(request.RemovedUsername);

            await _metaStore.SaveAsync(volumeName, header);
            RefreshMountedHeader(volumeName, header);
        });
    }

    /// <summary>
    /// crypto format v2: 自分宛ての全 epoch の GroupKey wraps とボリューム鍵状態を返す。
    /// 共有 v2 ボリューム（KeyEpoch ≥ 1）でのみ意味を持つ。未移行ボリュームでは MyGroupKeys は空。
    /// </summary>
    public async Task<E2eeGroupKeyInfoResponse?> GetGroupKeyInfoAsync(string volumeName, string username, CancellationToken ct = default)
    {
        var header = await LoadHeaderOrThrowAsync(volumeName);
        if (!header.IsE2ee)
            throw new VolumeException($"ボリューム '{volumeName}' は E2EE ボリュームではありません。");
        if (!header.HasUserAccess(username))
            throw new VolumeException($"ユーザー '{username}' はこのボリュームにアクセス権がありません。");

        var myKeys = new List<GroupKeyWrapResponse>();
        foreach (var entry in header.GroupKeyEpochs.OrderBy(e => e.Epoch))
        {
            if (!entry.Wraps.TryGetValue(username, out var wrap))
                continue;
            myKeys.Add(new GroupKeyWrapResponse(
                entry.Epoch,
                wrap.WrapType,
                wrap.WrappedMasterKey.Algorithm,
                Convert.ToBase64String(wrap.WrappedMasterKey.Nonce),
                Convert.ToBase64String(wrap.WrappedMasterKey.Ciphertext),
                Convert.ToBase64String(wrap.WrappedMasterKey.Tag),
                wrap.EphemeralPublicKey is not null ? Convert.ToBase64String(wrap.EphemeralPublicKey) : null));
        }

        bool hasLegacyFiles = header.KeyEpoch >= 1 && await HasLegacyFilesAsync(volumeName, ct);
        return new E2eeGroupKeyInfoResponse(header.EnsureVolumeId(), header.KeyEpoch, myKeys, hasLegacyFiles);
    }

    /// <summary>crypto format v2: remaining members（現行メンバー）の公開鍵一覧。オーナーが rotation 用に取得する。</summary>
    public async Task<IReadOnlyList<E2eeMemberPublicKeyResponse>> GetMemberPublicKeysAsync(
        string volumeName, string requesterUsername, CancellationToken ct = default)    {
        var header = await LoadHeaderOrThrowAsync(volumeName);
        if (!header.IsE2ee)
            throw new VolumeException($"ボリューム '{volumeName}' は E2EE ボリュームではありません。");
        if (header.OwnerUser != requesterUsername)
            throw new VolumeException("オーナーのみがメンバーの公開鍵一覧を取得できます。");

        var results = new List<E2eeMemberPublicKeyResponse>();
        foreach (var username in header.UserKeys.Keys)
        {
            results.Add(new E2eeMemberPublicKeyResponse(username, await GetAccountPublicKeyAsync(username)));
        }
        return results;
    }

    /// <summary>crypto 用の volumeId（AAD bind 用 stable identifier）。v2 未移行ボリュームでは null。</summary>
    public async Task<string?> GetVolumeIdAsync(string volumeName)
    {
        var header = await LoadHeaderIfExistsAsync(volumeName);
        return header?.VolumeId;
    }

    /// <summary>ボリューム内に v1 形式（KeyEpoch == 0）のファイルが残っているか。</summary>
    private async Task<bool> HasLegacyFilesAsync(string volumeName, CancellationToken ct)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var fileService = scope.ServiceProvider.GetRequiredService<E2eeFileService>();
        var files = await fileService.ListFilesAsync(volumeName, ct);
        return files.Files.Any(f => f.KeyEpoch == 0);
    }

    private async Task<string?> GetAccountPublicKeyAsync(string username)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var accountService = scope.ServiceProvider.GetRequiredService<AccountService>();
        return await accountService.GetPublicKeyAsync(username);
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
