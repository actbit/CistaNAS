using CistaNAS.Mobile.Core.Abstractions;

namespace CistaNAS.Mobile.Core.Services;

/// <summary>
/// モバイルアプリの手動コンポジションルート (DI コンテナ不使用。Desktop Client と同方針)。
/// プラットフォーム固有実装はヘッドプロジェクトからコンストラクタ注入する。
/// </summary>
public sealed class AppServices : IDisposable
{
    private readonly object _sessionLock = new();
    private CancellationTokenSource _sessionCancellation = new();

    public AppServices(ISecureKeyStore keyStore, IAppSettings settings,
        IFileCacheProvider fileCache, IExternalViewerLauncher externalViewer,
        HttpMessageHandler? httpHandler = null)
    {
        KeyStore = keyStore;
        Settings = settings;
        FileCache = fileCache;
        FileCache.Clear(); // 前回プロセスが終了した際の復号キャッシュも破棄する。
        ExternalViewer = externalViewer;
        EcdhKeys = new EcdhKeyManager();
        Session = new ApiSession(httpHandler);
        Transfer = new E2eeFileTransferService(Session.Api, E2ee);
        Session.Unauthorized += () =>
        {
            ClearSession();
            SessionExpired?.Invoke();
        };
    }

    public ISecureKeyStore KeyStore { get; }
    public IAppSettings Settings { get; }
    public IFileCacheProvider FileCache { get; }
    public IExternalViewerLauncher ExternalViewer { get; }
    public ApiSession Session { get; }
    public E2eeSession E2ee { get; } = new();
    public EcdhKeyManager EcdhKeys { get; }
    public E2eeFileTransferService Transfer { get; }
    public NavigationService Navigation { get; } = new();

    /// <summary>JWT 失効 (401) を検知したときに発火。UI はログイン画面へ戻す。</summary>
    public event Action? SessionExpired;

    public CancellationToken SessionCancellation
    {
        get { lock (_sessionLock) return _sessionCancellation.Token; }
    }

    /// <summary>転送を中止し、トークン・鍵・復号キャッシュをまとめて破棄する。</summary>
    public void ClearSession()
    {
        CancellationTokenSource previous;
        lock (_sessionLock)
        {
            previous = _sessionCancellation;
            _sessionCancellation = new CancellationTokenSource();
        }
        previous.Cancel();
        previous.Dispose();
        Session.ClearToken();
        E2ee.ClearKeys();
        FileCache.Clear();
    }

    public void Dispose()
    {
        ClearSession();
        _sessionCancellation.Dispose();
        Session.Dispose();
        E2ee.Dispose();
    }
}
