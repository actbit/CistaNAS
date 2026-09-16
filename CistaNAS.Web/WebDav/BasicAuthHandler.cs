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
    private readonly int _failedAuthLimitPerMinute;

    /// <summary>成功資格情報キャッシュ。キー = SHA256(user:pass)（平文保存を避ける）。</summary>
    private static readonly ConcurrentDictionary<string, CachedAuth> CredentialCache = new();
    private const int CacheCapacity = 1024;

    /// <summary>
    /// 認証失敗カウンタ（1 IP あたり 1 分の固定ウィンドウ）。
    /// 閾値超過の IP は Argon2id 検証（1 回あたり 64 MiB 相当のメモリ）を実行せず即座に失敗させる。
    /// webdav レートポリシー（既定 600 req/min）は正常操作用のため、失敗への絞りはここで行う
    /// （無いと Basic 総当たりがログインエンドポイント比 60 倍の速度 + CPU/メモリ負荷で攻撃可能）。
    /// </summary>
    private static readonly ConcurrentDictionary<string, (int Count, DateTimeOffset WindowStart)> FailedAuths = new();
    private static readonly TimeSpan FailureWindow = TimeSpan.FromMinutes(1);

    private sealed record CachedAuth(ClaimsPrincipal Principal, DateTimeOffset ExpiresAt, string Username);

    /// <summary>
    /// 指定ユーザーのキャッシュエントリを全て無効化する。
    /// パスワード変更・削除・ロール変更時に呼ぶ（キャッシュ TTL 内でも旧パスワード /
    /// 旧ロールの WebDAV リクエストを拒否させるため）。
    /// </summary>
    public static void InvalidateUser(string username)
    {
        foreach (var (key, value) in CredentialCache)
        {
            if (string.Equals(value.Username, username, StringComparison.OrdinalIgnoreCase))
                CredentialCache.TryRemove(key, out _);
        }
    }

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
        _failedAuthLimitPerMinute = cistaOptions.Value.Auth.WebDavFailedAuthLimitPerMinute;
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

            // 失敗スロットル: 閾値超過の IP は Argon2id 検証・DB 検証を実行せず即座に失敗させる
            string remoteIp = Context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            if (_failedAuthLimitPerMinute > 0 && IsOverFailureLimit(remoteIp))
                return AuthenticateResult.Fail("Too many failed authentication attempts.");

            var loginResponse = await _authService.AuthenticateAsync(username, password);
            if (loginResponse is null)
            {
                // ユーザーが存在しない場合もダミー計算を実行してタイミングを均一化
                Argon2Hasher.RunDummy();
                RecordAuthFailure(remoteIp);
                return AuthenticateResult.Fail("Invalid credentials.");
            }

            var principal = await _authService.GetPrincipalAsync(username);
            if (principal is null)
            {
                RecordAuthFailure(remoteIp);
                return AuthenticateResult.Fail("認証後にユーザーが見つかりません。");
            }

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

    private bool IsOverFailureLimit(string remoteIp)
    {
        var now = DateTimeOffset.UtcNow;
        return FailedAuths.TryGetValue(remoteIp, out var entry)
            && now - entry.WindowStart < FailureWindow
            && entry.Count >= _failedAuthLimitPerMinute;
    }

    private static void RecordAuthFailure(string remoteIp)
    {
        var now = DateTimeOffset.UtcNow;
        FailedAuths.AddOrUpdate(
            remoteIp,
            _ => (1, now),
            (_, entry) => now - entry.WindowStart >= FailureWindow ? (1, now) : (entry.Count + 1, entry.WindowStart));
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
        CredentialCache[cacheKey] = new CachedAuth(principal, DateTimeOffset.UtcNow.AddSeconds(_cacheSeconds), principal.Identity?.Name ?? "");
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.WWWAuthenticate = "Basic realm=\"CistaNAS\", charset=\"UTF-8\"";
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }
}
