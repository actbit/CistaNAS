using System.Security.Claims;
using System.Security.Cryptography;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Identity;
using CistaNAS.Web.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CistaNAS.Web.Services;

/// <summary>
/// 認証ビジネスロジック：パスワード検証と JWT 発行・検証。
/// 状態を持たないため Scoped 登録。Controllers / Blazor / /api/v1 から呼ばれる。
/// </summary>
public sealed class AuthService(
    AccountService accountService,
    JwtSigningKey signingKey,
    IOptions<CistaNasOptions> options,
    ILogger<AuthService> logger)
{
    /// <summary>
    /// 資格情報を検証し、成功時に JWT を発行する。失敗時は null。
    /// ロックアウト状態のユーザーは拒否し、失敗回数を追跡する。
    /// </summary>
    public async Task<LoginResponse?> AuthenticateAsync(string username, string password)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            return null;

        var user = await accountService.FindAsync(username);
        if (user is null)
        {
            // ユーザーが存在しない場合もダミー計算を実行してタイミングを均一化（ユーザー列挙対策）
            DummyHash(options.Value.Auth.Pbkdf2Iterations);
            logger.LogWarning("ログイン失敗: ユーザー '{Username}'", username);
            return null;
        }

        // ロックアウト状態のチェック（JWT ログイン・WebDAV 共通）
        if (await accountService.IsLockedOutAsync(user))
        {
            logger.LogWarning("ログイン拒否（ロックアウト中）: ユーザー '{Username}'", username);
            return null;
        }

        if (!await accountService.CheckPasswordAsync(user, password))
        {
            // 認証失敗回数をインクリメント（ロックアウトポリシーに連動）
            await accountService.AccessFailedAsync(user);
            logger.LogWarning("ログイン失敗: ユーザー '{Username}'", username);
            return null;
        }

        // 認証成功時に失敗カウンタをリセット
        await accountService.ResetAccessFailedCountAsync(user);

        logger.LogInformation("ログイン成功: ユーザー '{Username}'", username);
        return await IssueTokenAsync(user);
    }

    public async Task<LoginResponse> IssueTokenAsync(ApplicationUser user)
    {
        var jwt = options.Value.Jwt;
        var now = DateTimeOffset.UtcNow;
        var expires = now.AddMinutes(jwt.AccessTokenMinutes);

        var roles = await accountService.GetRolesAsync(user);
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserName ?? user.Id),
            new Claim(ClaimTypes.Name, user.UserName ?? user.Id),
        };
        foreach (var r in roles)
            claims.Add(new Claim(ClaimTypes.Role, r));

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = jwt.Issuer,
            Audience = jwt.Audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            Subject = new ClaimsIdentity(claims),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(signingKey.Value),
                SecurityAlgorithms.HmacSha256),
        };

        string token = new JsonWebTokenHandler().CreateToken(descriptor);
        return new LoginResponse(token, "Bearer", expires);
    }

    /// <summary>
    /// JWT を検証し ClaimsPrincipal を返す（Blazor ログイン状態復元用）。失敗時は null。
    /// </summary>
    public async Task<ClaimsPrincipal?> ValidateTokenAsync(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return null;

        var jwt = options.Value.Jwt;
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwt.Issuer,
            ValidateAudience = true,
            ValidAudience = jwt.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(signingKey.Value),
            ValidateLifetime = true,
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            ClockSkew = TimeSpan.FromSeconds(30),
        });

        return result.IsValid ? new ClaimsPrincipal(result.ClaimsIdentity) : null;
    }

    /// <summary>
    /// ユーザー名から ClaimsPrincipal を構築する（Basic 認証ハンドラ用）。
    /// JWT 再検証を回避し、DB から直接ロールを取得する。
    /// </summary>
    public async Task<ClaimsPrincipal?> GetPrincipalAsync(string username)
    {
        var user = await accountService.FindAsync(username);
        if (user is null) return null;
        var roles = await accountService.GetRolesAsync(user);
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, username),
        };
        foreach (var r in roles)
            claims.Add(new Claim(ClaimTypes.Role, r));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "BasicAuth"));
    }

    /// <summary>パスワードを変更し、全ボリュームの KEK を再ラップ。</summary>
    public async Task<bool> ChangePasswordAsync(string username, string oldPassword, string newPassword)
    {
        return await accountService.ChangePasswordAsync(username, oldPassword, newPassword);
    }

    /// <summary>
    /// ダミー PBKDF2 計算を実行してタイミングを均一化（ユーザー列挙対策）。
    /// 実認証（Identity の PBKDF2）の iteration に近い回数でダミー計算を実行し、
    /// ユーザー存在の有無によるタイミング差を最小化。
    /// 呼び出し毎にランダムソルトを生成し、事前計算攻撃を防止。
    /// </summary>
    private static void DummyHash(int iterations)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        Rfc2898DeriveBytes.Pbkdf2("dummy"u8, salt, iterations, HashAlgorithmName.SHA256, 32);
    }
}
