using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Crypto;
using CistaNAS.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.WebDav;

/// <summary>
/// WebDAV クライアント向け Basic 認証ハンドラ。
/// AuthService に対してパスワードを検証する。
/// Argon2id 検証は 1 回あたり 64 MiB 相当のメモリを消費するため、成功した資格情報を
/// 短時間キャッシュし（WebDavAuthCacheSeconds、既定 600 秒）、リクエスト毎の再検証を省略する。
/// </summary>
public sealed class BasicAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly AuthService _authService;
    private readonly int _cacheSeconds;

    /// <summary>成功資格情報キャッシュ。キー = SHA256(user:pass)（平文保存を避ける）。</summary>
    private static readonly ConcurrentDictionary<string, CachedAuth> CredentialCache = new();
    private const int CacheCapacity = 1024;

    private sealed record CachedAuth(ClaimsPrincipal Principal, DateTimeOffset ExpiresAt);

    public BasicAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        AuthService authService,
        IOptions<CistaNasOptions> cistaOptions)
        : base(options, logger, encoder)
    {
        _authService = authService;
        _cacheSeconds = cistaOptions.Value.Auth.WebDavAuthCacheSeconds;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authHeader))
            return AuthenticateResult.NoResult();

        string header = authHeader.ToString();
        if (!header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            return AuthenticateResult.NoResult();

        try
        {
            string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header["Basic ".Length..]));
            int colon = decoded.IndexOf(':');
            if (colon < 0) return AuthenticateResult.Fail("Invalid Basic Auth format.");

            string username = decoded[..colon];
            string password = decoded[(colon + 1)..];

            // 成功済み資格情報のキャッシュヒット（Argon2id 再検証を省略）
            string cacheKey = CacheKey(username, password);
            if (_cacheSeconds > 0
                && CredentialCache.TryGetValue(cacheKey, out var cached)
                && cached.ExpiresAt > DateTimeOffset.UtcNow)
            {
                return AuthenticateResult.Success(new AuthenticationTicket(cached.Principal, Scheme.Name));
            }

            var loginResponse = await _authService.AuthenticateAsync(username, password);
            if (loginResponse is null)
            {
                // ユーザーが存在しない場合もダミー計算を実行してタイミングを均一化
                Argon2Hasher.RunDummy();
                return AuthenticateResult.Fail("Invalid credentials.");
            }

            var principal = await _authService.GetPrincipalAsync(username);
            if (principal is null)
                return AuthenticateResult.Fail("認証後にユーザーが見つかりません。");

            if (_cacheSeconds > 0)
                StorePrincipal(cacheKey, principal);

            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }
        catch (FormatException)
        {
            return AuthenticateResult.Fail("Invalid Base64 in Basic Auth.");
        }
    }

    private static string CacheKey(string username, string password)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(username + "\n" + password)));

    private void StorePrincipal(string cacheKey, ClaimsPrincipal principal)
    {
        if (CredentialCache.Count >= CacheCapacity)
        {
            // 容量オーバー時は期限切れエントリを掃除
            foreach (var (key, value) in CredentialCache)
            {
                if (value.ExpiresAt <= DateTimeOffset.UtcNow)
                    CredentialCache.TryRemove(key, out _);
            }
        }
        CredentialCache[cacheKey] = new CachedAuth(principal, DateTimeOffset.UtcNow.AddSeconds(_cacheSeconds));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.WWWAuthenticate = "Basic realm=\"CistaNAS\", charset=\"UTF-8\"";
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }
}
