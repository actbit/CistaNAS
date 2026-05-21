using CistaNAS.Web.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace CistaNAS.Web.Services;

/// <summary>
/// UserStore の置き換え。UserManager をラップし、ユーザー CRUD・公開鍵管理・
/// セットアップウィザードを提供する。Scoped（UserManager が Scoped）。
/// </summary>
public sealed class AccountService(
    UserManager<ApplicationUser> userManager,
    RoleManager<ApplicationRole> roleManager,
    ILogger<AccountService> logger,
    IServiceScopeFactory scopeFactory)
{
    public async Task<bool> HasAnyUsersAsync()
        => await userManager.Users.AnyAsync();

    public async Task<ApplicationUser?> FindAsync(string username)
        => await userManager.FindByNameAsync(username);

    public async Task<IReadOnlyList<ApplicationUser>> ListAsync()
        => await userManager.Users.ToListAsync();

    public async Task<IReadOnlyList<(ApplicationUser User, IList<string> Roles)>> ListWithRolesAsync()
    {
        var users = await userManager.Users.ToListAsync();

        // 一括でユーザーロールを取得（N+1 回避）
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var userRoles = await db.UserRoles
            .Join(db.Roles, ur => ur.RoleId, r => r.Id, (ur, r) => new { ur.UserId, r.Name })
            .ToListAsync();
        var roleDict = userRoles.GroupBy(x => x.UserId)
            .ToDictionary(g => g.Key, g => (IList<string>)g.Select(x => x.Name).ToList());

        return users.Select(u =>
        {
            var roles = roleDict.TryGetValue(u.Id, out var r) ? r : Array.Empty<string>();
            return (u, (IList<string>)roles);
        }).ToList();
    }

    public async Task CreateUserAsync(string username, string password, string role = "user")
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentException.ThrowIfNullOrEmpty(password);

        await EnsureRoleAsync(role);

        var user = new ApplicationUser { UserName = username, Email = $"{username}@cista.local" };
        var result = await userManager.CreateAsync(user, password);
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join(", ", result.Errors.Select(e => e.Description)));

        var roleResult = await userManager.AddToRoleAsync(user, role);
        if (!roleResult.Succeeded)
            logger.LogWarning("ユーザー '{Username}' へのロール '{Role}' 割り当てに失敗: {Errors}",
                username, role, string.Join(", ", roleResult.Errors.Select(e => e.Description)));

        // ホームボリューム自動作成（スコープ外で実行）
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var volumeService = scope.ServiceProvider.GetRequiredService<VolumeService>();
            string homeName = $"home__{username}";
            volumeService.CreateInternal(homeName, username, password: null, encrypted: false);
        }
        catch { /* 既に存在する等は無視 */ }
    }

    public async Task DeleteUserAsync(string username)
    {
        var user = await userManager.FindByNameAsync(username)
            ?? throw new InvalidOperationException($"ユーザー '{username}' が見つかりません。");

        await userManager.DeleteAsync(user);

        // グループから除去
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var groupService = scope.ServiceProvider.GetRequiredService<GroupService>();
            await groupService.RemoveUserFromAllGroupsAsync(username);
        }
        catch { }

        // ホームボリューム削除
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var volumeService = scope.ServiceProvider.GetRequiredService<VolumeService>();
            volumeService.DeleteVolume($"home__{username}");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "ホームボリューム 'home__{Username}' の削除に失敗しました。", username);
        }
    }

    public async Task UpdateRoleAsync(string username, string newRole)
    {
        var user = await userManager.FindByNameAsync(username)
            ?? throw new InvalidOperationException($"ユーザー '{username}' が見つかりません。");

        await EnsureRoleAsync(newRole);

        var currentRoles = await userManager.GetRolesAsync(user);
        var removeResult = await userManager.RemoveFromRolesAsync(user, currentRoles);
        var addResult = await userManager.AddToRoleAsync(user, newRole);
        if (!addResult.Succeeded)
            logger.LogWarning("ユーザー '{Username}' のロール変更に失敗: {Errors}",
                username, string.Join(", ", addResult.Errors.Select(e => e.Description)));
    }

    public async Task<bool> IsAdminAsync(string username)
    {
        var user = await userManager.FindByNameAsync(username);
        return user is not null && await userManager.IsInRoleAsync(user, "admin");
    }

    public async Task<string?> GetPublicKeyAsync(string username)
    {
        var user = await userManager.FindByNameAsync(username);
        return user?.PublicKey;
    }

    public async Task UpdatePublicKeyAsync(string username, string publicKeyBase64)
    {
        var user = await userManager.FindByNameAsync(username)
            ?? throw new InvalidOperationException($"ユーザー '{username}' が見つかりません。");
        user.PublicKey = publicKeyBase64;
        var result = await userManager.UpdateAsync(user);
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join(", ", result.Errors.Select(e => e.Description)));
    }

    public async Task CreateInitialAdminAsync(string username, string password)
    {
        if (await userManager.Users.AnyAsync())
            throw new InvalidOperationException("ユーザーが既に存在します。");

        await EnsureRoleAsync("admin");

        var user = new ApplicationUser { UserName = username, Email = $"{username}@cista.local" };
        var result = await userManager.CreateAsync(user, password);
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join(", ", result.Errors.Select(e => e.Description)));

        var roleResult = await userManager.AddToRoleAsync(user, "admin");
        if (!roleResult.Succeeded)
            logger.LogWarning("初期管理者 '{Username}' への admin ロール割り当てに失敗: {Errors}",
                username, string.Join(", ", roleResult.Errors.Select(e => e.Description)));
    }

    public async Task<bool> CheckPasswordAsync(ApplicationUser user, string password)
        => await userManager.CheckPasswordAsync(user, password);

    /// <summary>パスワードを変更し、全ボリュームの KEK を再ラップ。</summary>
    public async Task<bool> ChangePasswordAsync(string username, string oldPassword, string newPassword)
    {
        var user = await userManager.FindByNameAsync(username);
        if (user is null) return false;

        if (!await userManager.CheckPasswordAsync(user, oldPassword))
            return false;

        // 先に Identity 側のパスワードを変更（失敗時は KEK 再ラップをスキップ）
        var result = await userManager.ChangePasswordAsync(user, oldPassword, newPassword);
        if (!result.Succeeded)
            return false;

        // KEK 再ラップ（スコープ外で実行）
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var volumeService = scope.ServiceProvider.GetRequiredService<VolumeService>();
            volumeService.RewrapAllForUser(username, oldPassword, newPassword);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "パスワード変更後の KEK 再ラップに失敗しました（ユーザー: {Username}）。", username);
        }

        return true;
    }

    public async Task<IList<string>> GetRolesAsync(ApplicationUser user)
        => await userManager.GetRolesAsync(user);

    private async Task EnsureRoleAsync(string roleName)
    {
        if (!await roleManager.RoleExistsAsync(roleName))
            await roleManager.CreateAsync(new ApplicationRole { Name = roleName });
    }
}
