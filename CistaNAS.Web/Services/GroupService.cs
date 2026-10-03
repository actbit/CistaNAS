using CistaNAS.Web.Identity;
using CistaNAS.Web.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CistaNAS.Web.Services;

/// <summary>
/// GroupStore の置き換え。EF Core でグループ CRUD を提供する。Scoped（AppDbContext が Scoped）。
/// </summary>
public sealed class GroupService(
    AppDbContext db,
    IServiceScopeFactory scopeFactory)
{
    public static void ValidateGroupName(string groupName)
    {
        ArgumentException.ThrowIfNullOrEmpty(groupName);
        if (groupName.Length > 64
            || groupName is "." or ".."
            || groupName.Contains('/', StringComparison.Ordinal)
            || groupName.Contains('\\', StringComparison.Ordinal)
            || groupName.Any(char.IsControl)
            || groupName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new InvalidOperationException("グループ名に使用できない文字が含まれています。");
    }

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

    /// <summary>ユーザーが所属するグループを DTO（EF ナビゲーションの循環参照回避）で返す。</summary>
    public async Task<List<GroupDto>> GetGroupDtosForUserAsync(string username)
        => (await GetGroupsForUserAsync(username))
            .Select(g => new GroupDto(g.GroupName, g.OwnerUser, g.CreatedAt,
                g.Members.Select(m => new MemberDto(m.Username)).ToList()))
            .ToList();

    public async Task<bool> IsMemberAsync(string groupName, string username)
        => await db.Groups
            .Where(g => g.GroupName == groupName && g.Members.Any(m => m.Username == username))
            .AnyAsync();

    public async Task CreateGroupAsync(string groupName, string ownerUser)
    {
        ValidateGroupName(groupName);
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

        // 先に全ボリュームから参照を除去する。DB のグループを先に消して
        // 参照除去をベストエフォートにすると、同名グループの再作成後に
        // 新メンバーが旧ボリュームへアクセスできるセキュリティ問題になる。
        // 途中で失敗した場合はグループを残して再試行可能にする。
        await using (var scope = scopeFactory.CreateAsyncScope())
        {
            var volumeService = scope.ServiceProvider.GetRequiredService<VolumeService>();
            await volumeService.RemoveGroupFromAllVolumesAsync(groupName);
        }

        db.Groups.Remove(group);
        await db.SaveChangesAsync();
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
