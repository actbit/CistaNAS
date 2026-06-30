using System.Net;
using System.Net.Http.Headers;
using CistaNAS.Wasm.Auth;
using Microsoft.AspNetCore.Components;

namespace CistaNAS.Wasm.Services.HttpHandlers;

/// <summary>
/// HttpClient の DelegatingHandler。
/// WasmAuthStateProvider から JWT を取得して Authorization ヘッダーに自動付与する。
/// また、認証済みユーザーに対する 401（JWT 期限切れ等）を検知した場合は
/// 自動的にログアウトしてログイン画面へ遷移する（UX の突然の操作不能を防ぐ）。
/// </summary>
public sealed class AuthHeaderHandler : DelegatingHandler
{
    private readonly WasmAuthStateProvider _auth;
    private readonly NavigationManager _nav;

    public AuthHeaderHandler(WasmAuthStateProvider auth, NavigationManager nav)
    {
        _auth = auth;
        _nav = nav;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (_auth.IsLoggedIn && !string.IsNullOrEmpty(_auth.Token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _auth.Token);
        }

        var response = await base.SendAsync(request, cancellationToken);

        // 認証済みユーザーへの 401 = JWT 期限切れ等 → ログアウトしてログイン画面へ。
        // 未認証時の 401（auth/setup, auth/login, auth/has-users 等の初回フロー）は無視する。
        if (response.StatusCode == HttpStatusCode.Unauthorized && _auth.IsLoggedIn)
        {
            await _auth.LogoutAsync();
            _nav.NavigateTo("/login", forceLoad: true);
        }

        return response;
    }
}
