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
    private string? _token;

    public ApiSession()
    {
        _authHandler = new AuthHeaderHandler(() => _token);
        _http = new HttpClient(_authHandler) { Timeout = TimeSpan.FromMinutes(5) };
        Api = new CistaNasApiClient(_http);
    }

    public CistaNasApiClient Api { get; }

    /// <summary>接続先サーバー URL (末尾スラッシュなし)。未接続時は null。</summary>
    public Uri? BaseAddress => _http.BaseAddress;

    /// <summary>サーバー URL を設定する (例: "http://192.168.1.10:5000")。</summary>
    public void ConfigureServer(string serverUrl)
    {
        if (!Uri.TryCreate(serverUrl.TrimEnd('/'), UriKind.Absolute, out var uri)
            || (uri.Scheme != "http" && uri.Scheme != "https"))
            throw new ArgumentException("サーバー URL が不正です。", nameof(serverUrl));
        _http.BaseAddress = uri;
    }

    public bool IsConfigured => _http.BaseAddress is not null;

    /// <summary>アクセストークン (JWT) を設定する。トークンはメモリのみに保持する。</summary>
    public void SetToken(string token)
    {
        _token = token;
        Api.SetToken(token);
    }

    /// <summary>トークンを破棄する (ログアウト / 401 時)。</summary>
    public void ClearToken()
    {
        _token = null;
        Api.ClearToken();
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
