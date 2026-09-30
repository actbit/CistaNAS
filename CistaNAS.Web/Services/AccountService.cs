using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Identity;
using CistaNAS.Web.Models;
using CistaNAS.Web.Volume;
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
    AppDbContext db,
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

    /// <summary>
    /// ユーザー一覧を DTO で返す。includeRoles=false のとき Roles を空にし、
    /// 一般ユーザーへのロール（誰が admin か）の漏洩を防ぐ。admin のみ includeRoles=true で呼ぶこと。
    /// sharingOnly=true のとき SharingEnabled=false のユーザーを除外する
    /// （共有先候補 picker 用。管理者用の一覧では false を渡すこと）。
    /// </summary>
    public async Task<List<UserDto>> ListUserDtosAsync(bool includeRoles = false, bool sharingOnly = false)
        => (await ListWithRolesAsync())
            .Where(u => !sharingOnly || u.User.SharingEnabled)
            .Select(u => new UserDto(
                u.User.UserName ?? "",
                includeRoles ? u.Roles : Array.Empty<string>(),
                u.User.SharingEnabled))
            .ToList();

    public async Task CreateUserAsync(string username, string password, string role = "user")
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentException.ThrowIfNullOrEmpty(password);

        await EnsureRoleAsync(role);

        var user = new ApplicationUser { UserName = username };
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
            string homeName = $"{VolumeHeader.HomePrefix}{username}";
            await volumeService.CreateInternalAsync(homeName, username, password: null, encrypted: false);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "ホームボリューム作成に失敗しました（ユーザー: {Username}）。", username);
        }
    }

    public async Task DeleteUserAsync(string username)
    {
        var user = await userManager.FindByNameAsync(username)
            ?? throw new InvalidOperationException($"ユーザー '{username}' が見つかりません。");

        // 最後の admin の削除を防止（管理不能状態を避ける）
        if (await userManager.IsInRoleAsync(user, "admin"))
        {
            var admins = await userManager.GetUsersInRoleAsync("admin");
            if (admins.Count <= 1)
                throw new InvalidOperationException("最後の管理者ユーザーは削除できません。");
        }

        await using var bootScope = scopeFactory.CreateAsyncScope();
        var volumeService = bootScope.ServiceProvider.GetRequiredService<VolumeService>();

        // home 以外の所有ボリュームが残っている場合は削除を拒否する
        // （オーナーが不在の孤児ボリュームになるのを防ぐ。削除/移管は管理者が事前に行う）
        var ownedVolumes = await volumeService.GetOwnedVolumeNamesAsync(username);
        if (ownedVolumes.Count > 0)
            throw new InvalidOperationException(
                $"ユーザー '{username}' がオーナーのボリュームが残っています: {string.Join(", ", ownedVolumes)}。削除または移管後に再度実行してください。");

        await userManager.DeleteAsync(user);

        // WebDAV Basic 認証の資格情報キャッシュを失効させる
        WebDav.BasicAuthHandler.InvalidateUser(username);

        // グループから除去
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var groupService = scope.ServiceProvider.GetRequiredService<GroupService>();
            await groupService.RemoveUserFromAllGroupsAsync(username);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "ユーザー '{Username}' のグループからの除去に失敗しました。", username);
        }

        // ホームボリューム削除
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            await volumeService.DeleteVolumeAsync($"{VolumeHeader.HomePrefix}{username}", username: null);
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

        // SecurityStamp 更新 → 既発行 JWT（旧ロールを主張するトークン）を失効させる。
        // WebDAV Basic の資格情報キャッシュも失効させる。
        await userManager.UpdateSecurityStampAsync(user);
        WebDav.BasicAuthHandler.InvalidateUser(username);
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

    /// <summary>ユーザー単位の共有有効フラグ。ユーザー不在時は false。</summary>
    public async Task<bool> IsSharingEnabledAsync(string username)
    {
        var user = await userManager.FindByNameAsync(username);
        return user?.SharingEnabled ?? false;
    }

    /// <summary>ユーザー単位の共有有効フラグを管理者が変更する。既存共有は自動 revoke しない。</summary>
    public async Task SetSharingEnabledAsync(string username, bool enabled)
    {
        var user = await userManager.FindByNameAsync(username)
            ?? throw new InvalidOperationException($"ユーザー '{username}' が見つかりません。");
        if (user.SharingEnabled == enabled) return;
        user.SharingEnabled = enabled;
        var result = await userManager.UpdateAsync(user);
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join(", ", result.Errors.Select(e => e.Description)));
    }

    /// <summary>ECDH identity の状態（salt / 導出バージョン / 登録済み公開鍵）。</summary>
    public sealed record EcdhIdentityInfo(byte[] IdentitySalt, int DerivationVersion, string? PublicKey);

    /// <summary>
    /// ECDH identity salt を取得する。未発行なら CSPRNG 32B で発行して保存する。
    /// salt は非秘密（サーバー DB 保存可）。秘密鍵はクライアント側でのみ導出され、サーバーに送られない。
    /// </summary>
    public async Task<EcdhIdentityInfo> GetOrCreateEcdhIdentityAsync(string username)
    {
        var user = await userManager.FindByNameAsync(username)
            ?? throw new InvalidOperationException($"ユーザー '{username}' が見つかりません。");

        if (user.EcdhIdentitySalt is not null && user.EcdhIdentitySalt.Length > 0
            && user.EcdhDerivationVersion > 0)
        {
            return new EcdhIdentityInfo(user.EcdhIdentitySalt, user.EcdhDerivationVersion, user.PublicKey);
        }

        user.EcdhIdentitySalt = EcdhIdentityKey.GenerateIdentitySalt();
        user.EcdhDerivationVersion = EcdhIdentityKey.CurrentDerivationVersion;
        var result = await userManager.UpdateAsync(user);
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join(", ", result.Errors.Select(e => e.Description)));
        return new EcdhIdentityInfo(user.EcdhIdentitySalt, user.EcdhDerivationVersion, user.PublicKey);
    }

    /// <summary>
    /// ECDH 公開鍵を登録する。決定論的導出のため、同一 identity（password / salt）からは常に
    /// 同一公開鍵が得られる。既存登録があり且つ allowRotation=false の場合は登録済み鍵の
    /// 上書きを拒否する（誤ったパスワードからの導出結果で既存 identity を潰さないため）。
    /// 鍵の更新は明示的な rotation 操作のみ。
    /// </summary>
    public async Task UpdatePublicKeyAsync(string username, string publicKeyBase64, bool allowRotation = false)
    {
        var user = await userManager.FindByNameAsync(username)
            ?? throw new InvalidOperationException($"ユーザー '{username}' が見つかりません。");
        if (user.PublicKey is not null && !allowRotation)
        {
            if (!string.Equals(user.PublicKey, publicKeyBase64, StringComparison.Ordinal))
                throw new InvalidOperationException(
                    "公開鍵は既に登録されています。鍵の更新は明示的な rotation 操作でのみ可能です。");
            return; // 同一鍵の再登録は冪等に成功扱い
        }
        user.PublicKey = publicKeyBase64;
        var result = await userManager.UpdateAsync(user);
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join(", ", result.Errors.Select(e => e.Description)));
    }

    public async Task CreateInitialAdminAsync(string username, string password)
    {
        await using var transaction = await db.Database.BeginTransactionAsync();
        if (await userManager.Users.AnyAsync())
            throw new InvalidOperationException("ユーザーが既に存在します。");

        await EnsureRoleAsync("admin");
        var user = new ApplicationUser { UserName = username };
        var result = await userManager.CreateAsync(user, password);
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join(", ", result.Errors.Select(e => e.Description)));

        var roleResult = await userManager.AddToRoleAsync(user, "admin");
        if (!roleResult.Succeeded)
            throw new InvalidOperationException(string.Join(", ", roleResult.Errors.Select(e => e.Description)));
        await transaction.CommitAsync();
    }

    public async Task<bool> CheckPasswordAsync(ApplicationUser user, string password)
        => await userManager.CheckPasswordAsync(user, password);

    /// <summary>ユーザーがロックアウト状態かどうかを確認。</summary>
    public async Task<bool> IsLockedOutAsync(ApplicationUser user)
        => await userManager.IsLockedOutAsync(user);

    /// <summary>認証失敗回数をインクリメント。</summary>
    public async Task AccessFailedAsync(ApplicationUser user)
        => await userManager.AccessFailedAsync(user);

    /// <summary>認証失敗カウンタをリセット。</summary>
    public async Task ResetAccessFailedCountAsync(ApplicationUser user)
        => await userManager.ResetAccessFailedCountAsync(user);

    /// <summary>パスワードを変更し、全ボリュームの KEK を再ラップ。</summary>
    public async Task<bool> ChangePasswordAsync(string username, string oldPassword, string newPassword)
    {
        var user = await userManager.FindByNameAsync(username);
        if (user is null) return false;

        if (!await userManager.CheckPasswordAsync(user, oldPassword))
            return false;

        // 先に Identity 側のパスワードを変更（失敗時は KEK 再ラップをスキップ）。
        // Identity の ChangePasswordAsync は SecurityStamp を更新するため、
        // この時点で既発行 JWT は全て無効化される（OnTokenValidated で検査）。
        var result = await userManager.ChangePasswordAsync(user, oldPassword, newPassword);
        if (!result.Succeeded)
            return false;

        // WebDAV Basic 認証の資格情報キャッシュを失効させる（TTL 残存での旧パスワード利用を防ぐ）
        WebDav.BasicAuthHandler.InvalidateUser(username);

        // KEK 再ラップ（二相コミット: 失敗時は処理済みボリュームが旧ラップへ復元されるため、
        // Identity 側のパスワードを旧値へロールバックすれば全ボリュームが旧パスワードで開ける） (H-5)
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var volumeService = scope.ServiceProvider.GetRequiredService<VolumeService>();
            await volumeService.RewrapAllForUserAsync(username, oldPassword, newPassword);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "パスワード変更後の KEK 再ラップに失敗しました（ユーザー: {Username}）。Identity パスワードを旧値にロールバックします。", username);
            try
            {
                // 二相コミットにより全ボリュームが旧ラップ（または Previous 退避）へ復元済みのため、
                // Identity パスワードを旧値に戻せば一貫した状態に戻る。
                var rollbackResult = await userManager.ChangePasswordAsync(user, newPassword, oldPassword);
                if (!rollbackResult.Succeeded)
                {
                    logger.LogCritical(
                        "Identity パスワードのロールバックにも失敗しました（ユーザー: {Username}）。手動復旧が必要です: {Errors}",
                        username, string.Join(", ", rollbackResult.Errors));
                }
            }
            catch (Exception rollbackEx)
            {
                logger.LogCritical(rollbackEx,
                    "Identity パスワードのロールバック中に例外（ユーザー: {Username}）。手動復旧が必要です。", username);
            }
            return false;  // 一貫性が壊れている可能性があるため失敗を返す
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
