using CistaNAS.Client.Api;

namespace CistaNAS.Mobile.Core.Services;

/// <summary>
/// サーバーへの HTTP 接続と認証トークンを管理するセッション。
/// HttpClient / CistaNasApiClient をここで一元保持する (手動コンポジション、DI コンテナ不使用)。
/// </summary>
public sealed class ApiSession : IDisposable
{
    private readonly AuthHeaderHandler _authHandler;
    private readonly HttpClient _http;
    // The destination and its credential must be observed as one state. Separate
    // reads could send a new server's token to the old destination during a switch.
    private sealed record AuthorizationState(Uri? Server, string? Token, long Version);
    private AuthorizationState _authorization = new(null, null, 0);
    private readonly AsyncLocal<long?> _requestVersion = new();

    public ApiSession(HttpMessageHandler? httpHandler = null)
    {
        _authHandler = new AuthHeaderHandler(() => Volatile.Read(ref _authorization).Token,
            () => Volatile.Read(ref _authorization).Server, () =>
            {
                var state = Volatile.Read(ref _authorization);
                return (state.Server, state.Token, state.Version);
            }, () => _requestVersion.Value);
        // リダイレクト先へログイン情報やアップロード本文を転送しない。
        _authHandler.InnerHandler = httpHandler ?? new HttpClientHandler { AllowAutoRedirect = false };
        // 接続失敗後もサーバーを変更できるよう、送信時に接続先を解決する。
        _http = new HttpClient(_authHandler)
        {
            BaseAddress = new Uri("http://session.invalid/"),
            Timeout = TimeSpan.FromMinutes(5)
        };
        Api = new CistaNasApiClient(_http);
    }

    public CistaNasApiClient Api { get; }

    /// <summary>接続先サーバー URL (末尾スラッシュなし)。未接続時は null。</summary>
    public Uri? BaseAddress => Volatile.Read(ref _authorization).Server;
    public long AuthenticationVersion => Volatile.Read(ref _authorization).Version;

    /// <summary>サーバー URL を設定する (例: "http://192.168.1.10:5000")。</summary>
    public void ConfigureServer(string serverUrl)
    {
        if (!Uri.TryCreate(serverUrl.TrimEnd('/'), UriKind.Absolute, out var uri)
            || (uri.Scheme != "http" && uri.Scheme != "https"))
            throw new ArgumentException("サーバー URL が不正です。", nameof(serverUrl));
        UpdateAuthorization(state => state.Server == uri ? state : new(uri, null, state.Version + 1));
    }

    public bool IsConfigured => BaseAddress is not null;

    /// <summary>アクセストークン (JWT) を設定する。トークンはメモリのみに保持する。</summary>
    public void SetToken(string token)
    {
        UpdateAuthorization(state => state with { Token = token, Version = state.Version + 1 });
    }

    /// <summary>トークンを破棄する (ログアウト / 401 時)。</summary>
    public void ClearToken()
    {
        UpdateAuthorization(state => state with { Token = null, Version = state.Version + 1 });
    }

    internal bool TrySetToken(string token, long expectedVersion)
    {
        var previous = Volatile.Read(ref _authorization);
        if (previous.Version != expectedVersion) return false;
        var next = previous with { Token = token, Version = previous.Version + 1 };
        return ReferenceEquals(Interlocked.CompareExchange(ref _authorization, next, previous), previous);
    }

    internal IDisposable BindRequests(long version)
    {
        long? previous = _requestVersion.Value;
        _requestVersion.Value = version;
        return new RequestBinding(() => _requestVersion.Value = previous);
    }

    private sealed class RequestBinding(Action release) : IDisposable
    {
        private Action? _release = release;
        public void Dispose() => Interlocked.Exchange(ref _release, null)?.Invoke();
    }

    private void UpdateAuthorization(Func<AuthorizationState, AuthorizationState> update)
    {
        AuthorizationState previous, next;
        do
        {
            previous = Volatile.Read(ref _authorization);
            next = update(previous);
        } while (!ReferenceEquals(Interlocked.CompareExchange(ref _authorization, next, previous), previous));
    }

    public event Action Unauthorized
    {
        add => _authHandler.Unauthorized += value;
        remove => _authHandler.Unauthorized -= value;
    }

    public void Dispose()
    {
        _http.Dispose();
    }
}
