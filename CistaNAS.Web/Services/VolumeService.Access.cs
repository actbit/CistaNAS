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
                header.AddUserWrap(targetUsername, targetPassword, masterKey, VolOpts.KdfIterations);
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

    /// <summary>ユーザーのパスワード変更時に全ボリュームの鍵を再ラップ。</summary>
    public Task RewrapAllForUserAsync(string username, string oldPassword, string newPassword)
    {
        return UnderMountGateAsync(async () =>
        {
            var volumeNames = await _metaStore.ListVolumeNamesAsync();
            foreach (var name in volumeNames)
            {
                var header = await LoadHeaderIfExistsAsync(name);
                if (header is null || !header.HasUserAccess(username)) continue;

                header.RewrapUser(username, oldPassword, newPassword, VolOpts.KdfIterations);
                await _metaStore.SaveAsync(name, header);
                RefreshMountedHeader(name, header);
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

    public Task RemoveGroupFromAllVolumesAsync(string groupName)
    {
        return UnderMountGateAsync(async () =>
        {
            var volumeNames = await _metaStore.ListVolumeNamesAsync();
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
    public Task SetUserQuotaAsync(string volumeName, string targetUsername, long maxBytes)
    {
        // _mountGate で並行 MountAsync / ヘッダ更新との競合を防ぐ (H-4)
        return UnderMountGateAsync(async () =>
        {
            var header = await LoadHeaderOrThrowAsync(volumeName);
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
