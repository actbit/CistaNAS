namespace CistaNAS.Mobile.Core.Services;

/// <summary>
/// 全リクエストに Bearer トークンを付与し、401 を検知したらイベント発火する DelegatingHandler。
/// (WASM フロントエンドの AuthHeaderHandler と同じ挙動。)
/// </summary>
public sealed class AuthHeaderHandler(Func<string?> tokenProvider) : DelegatingHandler
{
    /// <summary>アクセストークン失効 (401) を検知したときに発火。UI はログイン画面へ遷移する。</summary>
    public event Action? Unauthorized;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = tokenProvider();
        if (!string.IsNullOrEmpty(token))
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        var res = await base.SendAsync(request, cancellationToken);
        if (res.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            Unauthorized?.Invoke();
        return res;
    }
}
