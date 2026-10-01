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
    private long _authenticationVersion;
    private readonly SemaphoreSlim _storageGate = new(1, 1);
    private bool _disposed;

    public event Action? StateChanged;
    /// <summary>Await を挟む前に、前の認証に属する鍵・表示内容を破棄する。</summary>
    public event Action? SessionInvalidated;

    public WasmAuthStateProvider(IJSRuntime js)
    {
        _js = js;
    }

    /// <summary>現在の JWT トークン。</summary>
    public string? Token => _token;

    // A repeated login can receive the same JWT within a second. Its responses
    // still belong to a different authentication session.
    public long AuthenticationVersion => _authenticationVersion;

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
        ObjectDisposedException.ThrowIf(_disposed, this);
        long version = ++_authenticationVersion;
        _token = token;
        _expiresAt = expiresAt;

        // JWT の payload をデコードして ClaimsPrincipal を構築
        _user = ParseJwtClaims(token);
        SessionInvalidated?.Invoke();
        NotifyIfCurrent(version);

        await PersistAsync(version, token, expiresAt);
    }

    /// <summary>ログアウト。</summary>
    public async Task LogoutAsync()
    {
        if (_disposed) return;
        long version = ++_authenticationVersion;
        _user = null;
        _token = null;
        _expiresAt = null;
        SessionInvalidated?.Invoke();
        NotifyIfCurrent(version);

        await PersistAsync(version, null, null);
    }

    /// <summary>起動時に sessionStorage からトークンを復元。</summary>
    public async Task TryRestoreAsync()
    {
        long version = _authenticationVersion;
        try
        {
            string? token, expiresStr;
            await _storageGate.WaitAsync();
            try
            {
                if (!IsCurrent(version)) return;
                token = await _js.InvokeAsync<string?>("sessionStorage.getItem", "cista_jwt");
                if (!IsCurrent(version)) return;
                expiresStr = await _js.InvokeAsync<string?>("sessionStorage.getItem", "cista_jwt_expires");
            }
            finally { _storageGate.Release(); }
            if (!IsCurrent(version)) return;

            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(expiresStr)) return;

            var expires = DateTimeOffset.Parse(expiresStr);
            if (expires <= DateTimeOffset.UtcNow)
            {
                await LogoutAsync();
                return;
            }

            version = ++_authenticationVersion;
            _token = token;
            _expiresAt = expires;
            _user = ParseJwtClaims(token);
            SessionInvalidated?.Invoke();

            NotifyIfCurrent(version);
        }
        catch { /* 初期化失敗は無視 */ }
    }

    private bool IsCurrent(long version) => !_disposed && version == _authenticationVersion;

    private void NotifyIfCurrent(long version)
    {
        if (!IsCurrent(version)) return;
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        StateChanged?.Invoke();
    }

    private async Task PersistAsync(long version, string? token, DateTimeOffset? expires)
    {
        // Keep the token/expiration pair ordered. RAM invalidation still happens
        // immediately, before waiting for an older JS write or removal.
        await _storageGate.WaitAsync();
        try
        {
            if (!IsCurrent(version)) return;
            if (token is null)
            {
                await _js.InvokeVoidAsync("sessionStorage.removeItem", "cista_jwt");
                if (IsCurrent(version)) await _js.InvokeVoidAsync("sessionStorage.removeItem", "cista_jwt_expires");
            }
            else
            {
                await _js.InvokeVoidAsync("sessionStorage.setItem", "cista_jwt", token);
                if (IsCurrent(version)) await _js.InvokeVoidAsync("sessionStorage.setItem", "cista_jwt_expires", expires!.Value.ToString("O"));
            }
        }
        catch { /* JS 未初期化時は RAM 上の認証状態を維持する。 */ }
        finally { _storageGate.Release(); }
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
                    {
                        // Sub は AuthService が user.UserName を設定（常に存在）。
                        // JsonWebTokenHandler は ClaimTypes.Name を長いURIで出力し、
                        // WASM 側の "name" キー検索で拾えない場合があるため Sub から Name も設定。
                        var v = prop.Value.GetString() ?? "";
                        claims.Add(new Claim(ClaimTypes.NameIdentifier, v));
                        claims.Add(new Claim(ClaimTypes.Name, v));
                        break;
                    }
                    // サーバーは JsonWebTokenHandler（短縮マッピングなし）でクレームを出力するため、
                    // ClaimTypes.Name / Role は長い URI キーになる。短縮名と長い URI の両方を受け入れる。
                    case "unique_name" or "name" or "http://schemas.xml.org/ws/2005/05/identity/claims/name":
                        claims.Add(new Claim(ClaimTypes.Name, prop.Value.GetString() ?? ""));
                        break;
                    case "role" or "http://schemas.microsoft.com/ws/2008/06/identity/claims/role":
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

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _authenticationVersion++;
        _user = null; _token = null; _expiresAt = null;
        SessionInvalidated?.Invoke();
        StateChanged = null; SessionInvalidated = null;
        // In-flight JS calls may still release the managed semaphore.
    }
}
