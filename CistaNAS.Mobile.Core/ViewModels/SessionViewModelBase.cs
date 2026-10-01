using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>離れた画面の非同期操作が認証やナビゲーションを更新しないようにする。</summary>
public abstract class SessionViewModelBase : BusyViewModelBase, IDisposable
{
    private CancellationTokenSource _navigation = new();
    private bool _disposed;

    public override void OnNavigatedTo()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_navigation.IsCancellationRequested)
        {
            _navigation.Dispose();
            _navigation = new();
        }
    }

    public override void OnNavigatedFrom() { if (!_disposed) _navigation.Cancel(); }

    private protected ClientSessionOperation BeginOperation(AppServices app, CancellationToken ct)
        => app.BeginOperation(ct, _navigation.Token);

    protected Task RunSessionBusyAsync(Func<Task> action) => RunBusyAsync(async () =>
    {
        try { await action(); }
        catch (OperationCanceledException) { }
    });

    public void Dispose()
    {
        if (_disposed) return;
        OnNavigatedFrom();
        _disposed = true;
        _navigation.Dispose();
    }
}
