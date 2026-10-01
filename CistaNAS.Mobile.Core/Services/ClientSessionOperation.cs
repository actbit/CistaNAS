namespace CistaNAS.Mobile.Core.Services;

/// <summary>非同期操作の接続先・認証世代と画面寿命を固定する。</summary>
internal sealed class ClientSessionOperation : IDisposable
{
    private readonly AppServices _app;
    private readonly CancellationToken _session;
    private readonly long _version;
    private readonly CancellationTokenSource _cancellation;
    private readonly IDisposable _requestBinding;

    internal ClientSessionOperation(AppServices app, CancellationToken session, long version,
        CancellationToken command, CancellationToken navigation)
    {
        _app = app; _session = session; _version = version;
        _cancellation = CancellationTokenSource.CreateLinkedTokenSource(session, command, navigation);
        _requestBinding = app.Session.BindRequests(version);
    }

    public CancellationToken Cancellation => _cancellation.Token;
    public void EnsureCurrent() => Commit(static () => { });
    public void Commit(Action action) => _app.WithCurrentSession(_session, () =>
    {
        Cancellation.ThrowIfCancellationRequested();
        if (_app.Session.AuthenticationVersion != _version) throw new OperationCanceledException();
        action();
    });

    public void CompleteLogin(string token, string username, Action navigate) => Commit(() =>
    {
        if (!_app.Session.TrySetToken(token, _version)) throw new OperationCanceledException();
        _app.Settings.Username = username;
        _app.Settings.Save();
        // The next screen starts requests under the newly committed token.
        _requestBinding.Dispose();
        navigate();
    });

    public void Dispose() { _requestBinding.Dispose(); _cancellation.Dispose(); }
}
