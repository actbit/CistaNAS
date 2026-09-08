using CistaNAS.Mobile.Core.Abstractions;

namespace CistaNAS.Mobile.Core.Services;

/// <summary>
/// モバイルアプリの手動コンポジションルート (DI コンテナ不使用。Desktop Client と同方針)。
/// プラットフォーム固有実装はヘッドプロジェクトからコンストラクタ注入する。
/// </summary>
public sealed class AppServices : IDisposable
{
    public AppServices(ISecureKeyStore keyStore, IAppSettings settings,
        IFileCacheProvider fileCache, IExternalViewerLauncher externalViewer,
        HttpMessageHandler? httpHandler = null)
    {
        KeyStore = keyStore;
        Settings = settings;
        FileCache = fileCache;
        ExternalViewer = externalViewer;
        EcdhKeys = new EcdhKeyManager(keyStore);
        Session = new ApiSession(httpHandler);
        Transfer = new E2eeFileTransferService(Session.Api, E2ee);
        Session.Unauthorized += () => SessionExpired?.Invoke();
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

    public void Dispose()
    {
        Session.Dispose();
        E2ee.Dispose();
    }
}
