using System.Security.Claims;
using CistaNAS.Web.Services;

namespace CistaNAS.Web.Components.Auth;

/// <summary>
/// Blazor Interactive Server でのログイン状態管理。
/// HttpContext が無い Blazor 回線内で認証クレームを保持する。
/// </summary>
public sealed class AuthenticationStateService : IDisposable
{
    private readonly AuthService _authService;

    public event Action?StateChanged;

    public ClaimsPrincipal? User { get; private set; }
    public DateTimeOffset? ExpiresAt { get; private set; }
    public bool IsLoggedIn => User?.Identity?.IsAuthenticated == true
        && ExpiresAt.HasValue && ExpiresAt.Value > DateTimeOffset.UtcNow;

    public AuthenticationStateService(AuthService authService)
    {
        _authService = authService;
    }

    /// <summary>ログイン成功時に呼ぶ。JWT を ClaimsPrincipal に変換して保持。</summary>
    public async Task<bool> LoginAsync(string username, string password)
    {
        var res = await _authService.AuthenticateAsync(username, password);
        if (res is null) return false;

        User = await _authService.ValidateTokenAsync(res.AccessToken);
        Token = res.AccessToken;
        ExpiresAt = res.ExpiresAt;
        StateChanged?.Invoke();
        return true;
    }

    public void Logout()
    {
        User = null;
        Token = null;
        ExpiresAt = null;
        StateChanged?.Invoke();
    }

    public string? Token { get; private set; }

    public void Subscribe(Action handler) => StateChanged += handler;
    public void Unsubscribe(Action handler) => StateChanged -= handler;

    public void Dispose() => StateChanged = null;
}
