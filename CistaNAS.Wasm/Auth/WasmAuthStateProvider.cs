using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;

namespace CistaNAS.Wasm.Auth;

/// <summary>
/// WASM クライアントの認証状態管理。
/// JWT を sessionStorage に保持し、ClaimsPrincipal を提供する。
/// </summary>
public sealed class WasmAuthStateProvider : AuthenticationStateProvider, IDisposable
{
    private readonly IJSRuntime _js;
    private ClaimsPrincipal? _user;
    private string? _token;
    private DateTimeOffset? _expiresAt;

    public event Action? StateChanged;

    public WasmAuthStateProvider(IJSRuntime js)
    {
        _js = js;
    }

    /// <summary>現在の JWT トークン。</summary>
    public string? Token => _token;

    /// <summary>ログイン済みか。</summary>
    public bool IsLoggedIn =>
        _user?.Identity?.IsAuthenticated == true
        && _expiresAt.HasValue && _expiresAt.Value > DateTimeOffset.UtcNow;

    /// <summary>現在のユーザー名。</summary>
    public string CurrentUsername => _user?.Identity?.Name ?? "";

    /// <summary>admin ロールか。</summary>
    public bool IsAdmin => _user?.IsInRole("admin") == true;

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var user = IsLoggedIn ? _user! : new ClaimsPrincipal(new ClaimsIdentity());
        return Task.FromResult(new AuthenticationState(user));
    }

    /// <summary>ログイン成功時に呼ぶ。JWT を解析して ClaimsPrincipal を構築。</summary>
    public async Task SetTokenAsync(string token, DateTimeOffset expiresAt)
    {
        _token = token;
        _expiresAt = expiresAt;

        // JWT の payload をデコードして ClaimsPrincipal を構築
        _user = ParseJwtClaims(token);

        // sessionStorage に保存
        try
        {
            await _js.InvokeVoidAsync("sessionStorage.setItem", "cista_jwt", token);
            await _js.InvokeVoidAsync("sessionStorage.setItem", "cista_jwt_expires", expiresAt.ToString("O"));
        }
        catch { /* JS 未初期化時は無視 */ }

        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        StateChanged?.Invoke();
    }

    /// <summary>ログアウト。</summary>
    public async Task LogoutAsync()
    {
        _user = null;
        _token = null;
        _expiresAt = null;

        try
        {
            await _js.InvokeVoidAsync("sessionStorage.removeItem", "cista_jwt");
            await _js.InvokeVoidAsync("sessionStorage.removeItem", "cista_jwt_expires");
        }
        catch { /* JS 未初期化時は無視 */ }

        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        StateChanged?.Invoke();
    }

    /// <summary>起動時に sessionStorage からトークンを復元。</summary>
    public async Task TryRestoreAsync()
    {
        try
        {
            var token = await _js.InvokeAsync<string?>("sessionStorage.getItem", "cista_jwt");
            var expiresStr = await _js.InvokeAsync<string?>("sessionStorage.getItem", "cista_jwt_expires");

            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(expiresStr)) return;

            var expires = DateTimeOffset.Parse(expiresStr);
            if (expires <= DateTimeOffset.UtcNow)
            {
                await LogoutAsync();
                return;
            }

            _token = token;
            _expiresAt = expires;
            _user = ParseJwtClaims(token);

            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
            StateChanged?.Invoke();
        }
        catch { /* 初期化失敗は無視 */ }
    }

    /// <summary>JWT の payload をデコードして ClaimsPrincipal を構築。</summary>
    private static ClaimsPrincipal ParseJwtClaims(string token)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3) return new ClaimsPrincipal(new ClaimsIdentity());

            // Base64url デコード
            var payload = parts[1];
            payload = payload.Replace('-', '+').Replace('_', '/');
            while (payload.Length % 4 != 0) payload += '=';
            var bytes = Convert.FromBase64String(payload);
            var json = System.Text.Encoding.UTF8.GetString(bytes);

            // JSON をパースして claims に変換
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var claims = new List<Claim>();

            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                switch (prop.Name)
                {
                    case "sub":
                        claims.Add(new Claim(ClaimTypes.NameIdentifier, prop.Value.GetString() ?? ""));
                        break;
                    case "unique_name" or "name":
                        claims.Add(new Claim(ClaimTypes.Name, prop.Value.GetString() ?? ""));
                        break;
                    case "role":
                        if (prop.Value.ValueKind == System.Text.Json.JsonValueKind.Array)
                        {
                            foreach (var role in prop.Value.EnumerateArray())
                                claims.Add(new Claim(ClaimTypes.Role, role.GetString() ?? ""));
                        }
                        else
                        {
                            claims.Add(new Claim(ClaimTypes.Role, prop.Value.GetString() ?? ""));
                        }
                        break;
                }
            }

            return new ClaimsPrincipal(new ClaimsIdentity(claims, "jwt"));
        }
        catch
        {
            return new ClaimsPrincipal(new ClaimsIdentity());
        }
    }

    public void Dispose() => StateChanged = null;
}
