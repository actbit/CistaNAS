namespace CistaNAS.Mobile.Core.Services;

/// <summary>
/// 全リクエストに Bearer トークンを付与し、401 を検知したらイベント発火する DelegatingHandler。
/// (WASM フロントエンドの AuthHeaderHandler と同じ挙動。)
/// </summary>
public sealed class AuthHeaderHandler(Func<string?> tokenProvider, Func<Uri?>? serverProvider = null,
    Func<(Uri? Server, string? Token, long Version)>? authorizationProvider = null,
    Func<long?>? requestVersionProvider = null) : DelegatingHandler
{
    /// <summary>アクセストークン失効 (401) を検知したときに発火。UI はログイン画面へ遷移する。</summary>
    public event Action? Unauthorized;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var sent = authorizationProvider?.Invoke();
        if (requestVersionProvider?.Invoke() is long expectedVersion && sent?.Version != expectedVersion)
            throw new OperationCanceledException("操作の接続先または認証状態が変更されました。");
        Uri? sentServer = sent.HasValue ? sent.Value.Server : serverProvider?.Invoke();
        string? token = sent.HasValue ? sent.Value.Token : tokenProvider();
        if (serverProvider is not null || sent.HasValue)
        {
            Uri server = sentServer ?? throw new InvalidOperationException("サーバーが未設定です。");
            request.RequestUri = new Uri(server, request.RequestUri!.PathAndQuery);
        }
        // HttpClient may already have copied an older default Authorization
        // header before logout or a server switch. Always replace that copy.
        request.Headers.Authorization = string.IsNullOrEmpty(token) ? null
            : new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        var res = await base.SendAsync(request, cancellationToken);
        var current = authorizationProvider?.Invoke();
        if (res.StatusCode == System.Net.HttpStatusCode.Unauthorized && !string.IsNullOrEmpty(token) &&
            token == (current.HasValue ? current.Value.Token : tokenProvider()) &&
            sentServer == (current.HasValue ? current.Value.Server : serverProvider?.Invoke()) &&
            (!sent.HasValue || current?.Version == sent.Value.Version))
            Unauthorized?.Invoke();
        return res;
    }
}
