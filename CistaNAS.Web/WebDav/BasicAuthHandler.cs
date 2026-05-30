using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.WebDav;

/// <summary>
/// WebDAV クライアント向け Basic 認証ハンドラ。
/// UserStore に対してパスワードを検証する。
/// </summary>
public sealed class BasicAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly AuthService _authService;
    private readonly int _iterations;

    public BasicAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        AuthService authService,
        IOptions<CistaNasOptions> cistaOptions)
        : base(options, logger, encoder)
    {
        _authService = authService;
        _iterations = cistaOptions.Value.Auth.Pbkdf2Iterations;
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

            var loginResponse = await _authService.AuthenticateAsync(username, password);
            if (loginResponse is null)
            {
                // ユーザーが存在しない場合もダミー計算を実行してタイミングを均一化
                DummyHash(_iterations);
                return AuthenticateResult.Fail("Invalid credentials.");
            }

            var principal = await _authService.GetPrincipalAsync(username);
            if (principal is null)
                return AuthenticateResult.Fail("認証後にユーザーが見つかりません。");

            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }
        catch (FormatException)
        {
            return AuthenticateResult.Fail("Invalid Base64 in Basic Auth.");
        }
    }

    private static void DummyHash(int iterations)
    {
        // 実認証（Identity の PBKDF2）の iteration に近い回数でダミー計算を実行し、
        // ユーザー存在の有無によるタイミング差を最小化。
        // 呼び出し毎にランダムソルトを生成し、事前計算攻撃を防止。
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        Rfc2898DeriveBytes.Pbkdf2("dummy"u8, salt, iterations, HashAlgorithmName.SHA256, 32);
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.WWWAuthenticate = "Basic realm=\"CistaNAS\", charset=\"UTF-8\"";
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }
}
