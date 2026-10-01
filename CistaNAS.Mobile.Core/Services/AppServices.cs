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
        IFileViewerLauncher viewer,
        HttpMessageHandler? httpHandler = null)
    {
        KeyStore = keyStore;
        Settings = settings;
        Viewer = viewer;
        Viewer.Clear();
        EcdhKeys = new EcdhKeyManager();
        Session = new ApiSession(httpHandler);
        Transfer = new E2eeFileTransferService(Session.Api, E2ee);
        StreamingFiles = new StreamingFileService(Session.Api, E2ee);
        BufferedFiles = new BufferedFileService(StreamingFiles);
        Session.Unauthorized += () =>
        {
            ClearSession();
            SessionExpired?.Invoke();
        };
    }

    public ISecureKeyStore KeyStore { get; }
    public IAppSettings Settings { get; }
    public IFileViewerLauncher Viewer { get; }
    public ApiSession Session { get; }
    public E2eeSession E2ee { get; } = new();
    public EcdhKeyManager EcdhKeys { get; }
    public E2eeFileTransferService Transfer { get; }
    public StreamingFileService StreamingFiles { get; }
    public BufferedFileService BufferedFiles { get; }
    public NavigationService Navigation { get; } = new();

    /// <summary>JWT 失効 (401) を検知したときに発火。UI はログイン画面へ戻す。</summary>
    public event Action? SessionExpired;

    public CancellationToken SessionCancellation
    {
        get { lock (_sessionLock) return _sessionCancellation.Token; }
    }

    // Install keys only into the session that started the mount. Checking the
    // token under the same lock as logout also closes the check/publish race.
    internal void WithCurrentSession(CancellationToken session, Action action)
    {
        lock (_sessionLock)
        {
            if (session != _sessionCancellation.Token) throw new OperationCanceledException(session);
            session.ThrowIfCancellationRequested();
            action();
        }
    }

    internal ClientSessionOperation BeginOperation(CancellationToken command, CancellationToken navigation)
    {
        lock (_sessionLock)
            return new(this, _sessionCancellation.Token, Session.AuthenticationVersion, command, navigation);
    }

    /// <summary>転送を中止し、表示画面のRAM上の内容・トークン・鍵を破棄する。</summary>
    public void ClearSession()
    {
        CancellationTokenSource previous;
        lock (_sessionLock)
        {
            previous = _sessionCancellation;
            _sessionCancellation = new CancellationTokenSource();
            E2ee.ClearKeys();
            Session.ClearToken();
        }
        previous.Cancel();
        previous.Dispose();
        Viewer.Clear();
    }

    public void Dispose()
    {
        ClearSession();
        _sessionCancellation.Dispose();
        Session.Dispose();
        E2ee.Dispose();
    }
}
