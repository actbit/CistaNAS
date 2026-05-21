using System.Security.Claims;
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
    UserManager<ApplicationUser> userManager,
    JwtSigningKey signingKey,
    IOptions<CistaNasOptions> options,
    ILogger<AuthService> logger)
{
    /// <summary>
    /// 資格情報を検証し、成功時に JWT を発行する。失敗時は null。
    /// </summary>
    public async Task<LoginResponse?> AuthenticateAsync(string username, string password)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            return null;

        var user = await accountService.FindAsync(username);
        if (user is null || !await accountService.CheckPasswordAsync(user, password))
        {
            logger.LogWarning("ログイン失敗: ユーザー '{Username}'", username);
            return null;
        }

        logger.LogInformation("ログイン成功: ユーザー '{Username}'", username);
        return await IssueTokenAsync(user);
    }

    public async Task<LoginResponse> IssueTokenAsync(ApplicationUser user)
    {
        var jwt = options.Value.Jwt;
        var now = DateTimeOffset.UtcNow;
        var expires = now.AddMinutes(jwt.AccessTokenMinutes);

        var roles = await accountService.GetRolesAsync(user);
        var role = roles.FirstOrDefault() ?? "user";

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = jwt.Issuer,
            Audience = jwt.Audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            Subject = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName ?? user.Id),
                new Claim(ClaimTypes.Name, user.UserName ?? user.Id),
                new Claim(ClaimTypes.Role, role),
            ]),
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
            ClockSkew = TimeSpan.FromSeconds(30),
        });

        return result.IsValid ? new ClaimsPrincipal(result.ClaimsIdentity) : null;
    }

    /// <summary>パスワードを変更し、全ボリュームの KEK を再ラップ。</summary>
    public async Task<bool> ChangePasswordAsync(string username, string oldPassword, string newPassword)
    {
        return await accountService.ChangePasswordAsync(username, oldPassword, newPassword);
    }
}
