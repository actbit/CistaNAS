using System.Security.Cryptography;
using CistaNAS.Web.Identity;
using CistaNAS.Web.Models;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;

namespace CistaNAS.Web.Services;

public sealed partial class VolumeService
{
    /// <summary>ボリュームが指定ユーザーのアクセス権を持つか。</summary>
    public async Task<bool> HasAccessAsync(string volumeName, string username)
    {
        var header = await LoadHeaderIfExistsAsync(volumeName);
        if (header is null) return false;

        // グループ共有が設定されていないボリュームでは、グループ判定は常に false になるため
        // membership の DB クエリを省略する (E2EE ボリュームは GrantGroupAccessAsync で
        // グループ共有が禁止されているため、常に AuthorizedGroups が空 → 毎リクエストの
        // アクセス確認で無駄なクエリが発生していた)
        var userGroups = header.AuthorizedGroups.Count > 0
            ? await GetGroupsForUserAsync(username)
            : [];
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
    public Task GrantAccessAsync(string volumeName, string granterUsername, string granterPassword,
        string targetUsername, string targetPassword)
    {
        ArgumentException.ThrowIfNullOrEmpty(granterUsername);
        ArgumentException.ThrowIfNullOrEmpty(granterPassword);
        ArgumentException.ThrowIfNullOrEmpty(targetUsername);
        ArgumentException.ThrowIfNullOrEmpty(targetPassword);

        return UnderMountGateAsync(async () =>
        {
            var header = await LoadHeaderOrThrowAsync(volumeName);
            if (header.OwnerUser != granterUsername)
                throw new VolumeException("オーナーのみがアクセス権を付与できます。");

            byte[]? masterKey = header.UnwrapMasterKey(granterUsername, granterPassword)
                ?? throw new VolumeException("付与者の認証情報が正しくありません。");

            try
            {
                header.AddUserWrap(targetUsername, targetPassword, masterKey, VolOpts.ToKdfSpec());
                await _metaStore.SaveAsync(volumeName, header);
                RefreshMountedHeader(volumeName, header);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(masterKey);
            }
        });
    }

    /// <summary>ボリュームからユーザーのアクセス権を剥奪。</summary>
    public Task RevokeAccessAsync(string volumeName, string revokerUsername, string targetUsername)
    {
        return UnderMountGateAsync(async () =>
        {
            var header = await LoadHeaderOrThrowAsync(volumeName);
            if (header.OwnerUser != revokerUsername)
                throw new VolumeException("オーナーのみがアクセス権を剥奪できます。");
            if (targetUsername == header.OwnerUser)
                throw new VolumeException("オーナーのアクセス権は剥奪できません。");

            header.RemoveUserWrap(targetUsername);
            await _metaStore.SaveAsync(volumeName, header);
            RefreshMountedHeader(volumeName, header);
        });
    }

    /// <summary>
    /// ユーザーのパスワード変更時に全ボリュームの鍵を再ラップする（二相コミット）。
    /// 第 1 相: 全ボリュームのラップを新パスワードへ張り替え、旧ラップを Previous* に退避して保存。
    /// 第 2 相: 全ボリュームの準備完了後に旧ラップを除去して確定。
    /// 途中で失敗した場合は処理済みボリュームを旧エントリへ復元するため、
    /// 「旧パスワードでしか開けない / 新パスワードでしか開けない」ボリュームが混在する
    /// KEK 分裂（データ可用性の喪失）が発生しない。復元の保存に失敗した場合も
    /// 退避中のボリュームは旧・新どちらのパスワードでもアンラップ可能。
    /// </summary>
    public async Task RewrapAllForUserAsync(string username, string oldPassword, string newPassword)
    {
        // ボリューム一覧はゲート外で取得し、ゲート保持時間を最小化する
        var volumeNames = await _metaStore.ListVolumeNamesAsync();

        await UnderMountGateAsync(async () =>
        {
            // ロールバック用に旧エントリをスナップショット（第 1 相 / 第 2 相のどちらで
            // 失敗しても、このエントリへ戻せば旧パスワードで開ける状態に戻る）
            var prepared = new List<string>();
            var oldEntries = new Dictionary<string, VolumeHeader.UserWrappedKey>(StringComparer.Ordinal);

            try
            {
                // 第 1 相: 新ラップへ張り替え（旧ラップ退避つき）
                foreach (var name in volumeNames)
                {
                    var header = await LoadHeaderIfExistsAsync(name);
                    if (header is null || !header.HasUserAccess(username)) continue;

                    oldEntries[name] = header.UserKeys[username];
                    header.BeginRewrapUser(username, oldPassword, newPassword, VolOpts.ToKdfSpec());
                    await _metaStore.SaveAsync(name, header);
                    RefreshMountedHeader(name, header);
                    prepared.Add(name);
                }

                // 第 2 相: 旧ラップを除去して確定
                foreach (var name in prepared)
                {
                    var header = await LoadHeaderIfExistsAsync(name);
                    if (header is null) continue;
                    header.CommitRewrapUser(username);
                    await _metaStore.SaveAsync(name, header);
                    RefreshMountedHeader(name, header);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "パスワード変更の KEK 再ラップが失敗しました（ユーザー: {Username}）。処理済み {Count} ボリュームを旧ラップへ復元します。",
                    username, prepared.Count);

                // ベストエフォートで旧エントリへ復元（第 1 相・第 2 相どちらで失敗しても有効）。
                // 復元の保存にも失敗したボリュームは Previous* 退避中のため旧パスワードで開ける。
                foreach (var name in prepared)
                {
                    try
                    {
                        var header = await LoadHeaderIfExistsAsync(name);
                        if (header is null || !oldEntries.TryGetValue(name, out var oldEntry)) continue;
                        header.UserKeys[username] = oldEntry;
                        await _metaStore.SaveAsync(name, header);
                        RefreshMountedHeader(name, header);
                    }
                    catch (Exception restoreEx)
                    {
                        _logger.LogCritical(restoreEx,
                            "ボリューム '{Volume}' の旧ラップ復元に失敗しました（ユーザー: {Username}）。Previous ラップが残存するため旧・新どちらのパスワードでも開けます。手動での整合確認を推奨。",
                            name, username);
                    }
                }
                throw;
            }
        });
    }

    // ---- グループアクセス ----

    public Task GrantGroupAccessAsync(string volumeName, string granterUsername, string groupName)
    {
        return UnderMountGateAsync(async () =>
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
        });
    }

    public Task RevokeGroupAccessAsync(string volumeName, string revokerUsername, string groupName)
    {
        return UnderMountGateAsync(async () =>
        {
            var header = await LoadHeaderOrThrowAsync(volumeName);
            if (header.OwnerUser != revokerUsername)
                throw new VolumeException("オーナーのみがグループアクセスを剥奪できます。");
            if (!header.AuthorizedGroups.Remove(groupName))
                throw new VolumeException($"グループ '{groupName}' はこのボリュームにアクセス権がありません。");

            await _metaStore.SaveAsync(volumeName, header);
            RefreshMountedHeader(volumeName, header);
        });
    }

    public async Task RemoveGroupFromAllVolumesAsync(string groupName)
    {
        // ボリューム一覧はゲート外で取得し、ゲート保持時間を最小化する
        var volumeNames = await _metaStore.ListVolumeNamesAsync();

        await UnderMountGateAsync(async () =>
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
        });
    }

    // ---- ユーザークオータ ----

    /// <summary>ユーザーのクオータを設定する（ボリュームオーナーのみ）。</summary>
    public Task SetUserQuotaAsync(string volumeName, string requesterUsername, string targetUsername, long maxBytes)
    {
        // _mountGate で並行 MountAsync / ヘッダ更新との競合を防ぐ (H-4)
        return UnderMountGateAsync(async () =>
        {
            var header = await LoadHeaderOrThrowAsync(volumeName);
            // サービス層でもオーナー確認（API の VolumeOwner ポリシーのみに頼らない
            // defense-in-depth）。Grant*/Revoke* 系と一貫した二重チェック。
            if (header.OwnerUser != requesterUsername)
                throw new VolumeException("オーナーのみがクオータを設定できます。");
            header.UserQuotas[targetUsername] = maxBytes;
            await _metaStore.SaveAsync(volumeName, header);

            // マウント済みの場合、RefreshMountedHeader で全体を置換して
            // 他のスレッドからの読み取りとの競合を防ぐ
            RefreshMountedHeader(volumeName, header);
        });
    }

    // ---- DB アクセスヘルパ（Access / E2ee 両方で使用） ----

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
}
