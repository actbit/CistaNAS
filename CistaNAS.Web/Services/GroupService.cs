using CistaNAS.Web.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CistaNAS.Web.Services;

/// <summary>
/// GroupStore の置き換え。EF Core でグループ CRUD を提供する。Scoped（AppDbContext が Scoped）。
/// </summary>
public sealed class GroupService(
    AppDbContext db,
    ILogger<GroupService> logger,
    IServiceScopeFactory scopeFactory)
{
    public async Task<IReadOnlyList<GroupEntity>> ListGroupsAsync()
        => await db.Groups.AsNoTracking().ToListAsync();

    public async Task<GroupEntity?> FindAsync(string groupName)
        => await db.Groups.Include(g => g.Members).FirstOrDefaultAsync(
            g => g.GroupName == groupName);

    public async Task<List<GroupEntity>> GetGroupsForUserAsync(string username)
        => await db.Groups
            .Include(g => g.Members)
            .Where(g => g.Members.Any(m => m.Username == username))
            .ToListAsync();

    public async Task<bool> IsMemberAsync(string groupName, string username)
        => await db.Groups
            .Where(g => g.GroupName == groupName && g.Members.Any(m => m.Username == username))
            .AnyAsync();

    public async Task CreateGroupAsync(string groupName, string ownerUser)
    {
        ArgumentException.ThrowIfNullOrEmpty(groupName);
        ArgumentException.ThrowIfNullOrEmpty(ownerUser);

        if (await db.Groups.AnyAsync(g => g.GroupName == groupName))
            throw new InvalidOperationException($"グループ '{groupName}' は既に存在します。");

        db.Groups.Add(new GroupEntity
        {
            GroupName = groupName,
            OwnerUser = ownerUser,
            CreatedAt = DateTimeOffset.UtcNow,
            Members = [new GroupMemberEntity { Username = ownerUser }],
        });
        await db.SaveChangesAsync();
    }

    public async Task DeleteGroupAsync(string groupName, string requester)
    {
        var group = await db.Groups.Include(g => g.Members)
            .FirstOrDefaultAsync(g => g.GroupName == groupName)
            ?? throw new InvalidOperationException($"グループ '{groupName}' が見つかりません。");

        if (group.OwnerUser != requester)
            throw new InvalidOperationException("オーナーのみがグループを削除できます。");

        db.Groups.Remove(group);
        await db.SaveChangesAsync();

        // ボリュームからグループ参照を除去（スコープ外で実行）
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var volumeService = scope.ServiceProvider.GetRequiredService<VolumeService>();
            volumeService.RemoveGroupFromAllVolumes(groupName);
        }
        catch { }
    }

    public async Task AddMemberAsync(string groupName, string requester, string username)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);

        var group = await FindAsync(groupName)
            ?? throw new InvalidOperationException($"グループ '{groupName}' が見つかりません。");

        if (group.OwnerUser != requester)
            throw new InvalidOperationException("オーナーのみがメンバーを追加できます。");

        if (group.Members.Any(m => m.Username == username))
            throw new InvalidOperationException($"ユーザー '{username}' は既にメンバーです。");

        group.Members.Add(new GroupMemberEntity { Username = username });
        await db.SaveChangesAsync();
    }

    public async Task RemoveMemberAsync(string groupName, string requester, string username)
    {
        var group = await FindAsync(groupName)
            ?? throw new InvalidOperationException($"グループ '{groupName}' が見つかりません。");

        if (group.OwnerUser != requester)
            throw new InvalidOperationException("オーナーのみがメンバーを削除できます。");
        if (username == group.OwnerUser)
            throw new InvalidOperationException("オーナーは削除できません。");

        var member = group.Members.FirstOrDefault(m => m.Username == username)
            ?? throw new InvalidOperationException($"ユーザー '{username}' はメンバーではありません。");

        db.GroupMembers.Remove(member);
        await db.SaveChangesAsync();
    }

    public async Task RemoveUserFromAllGroupsAsync(string username)
    {
        var memberships = await db.GroupMembers
            .Where(m => m.Username == username)
            .ToListAsync();

        if (memberships.Count > 0)
        {
            db.GroupMembers.RemoveRange(memberships);
            await db.SaveChangesAsync();
        }
    }
}
