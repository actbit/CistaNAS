using CistaNAS.Wasm.Auth;

namespace CistaNAS.Wasm.Services.HttpHandlers;

/// <summary>
/// HttpClient の DelegatingHandler。
/// WasmAuthStateProvider から JWT を取得して Authorization ヘッダーに自動付与する。
/// </summary>
public sealed class AuthHeaderHandler : DelegatingHandler
{
    private readonly WasmAuthStateProvider _auth;

    public AuthHeaderHandler(WasmAuthStateProvider auth)
    {
        _auth = auth;
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (_auth.IsLoggedIn && !string.IsNullOrEmpty(_auth.Token))
        {
            request.Headers.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _auth.Token);
        }
        return base.SendAsync(request, cancellationToken);
    }
}
