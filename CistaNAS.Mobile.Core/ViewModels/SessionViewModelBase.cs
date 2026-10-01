using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>離れた画面の非同期操作が認証やナビゲーションを更新しないようにする。</summary>
public abstract class SessionViewModelBase : BusyViewModelBase, IDisposable
{
    private CancellationTokenSource _navigation = new();
    private bool _disposed;
    private long _busyVersion;

    public override void OnNavigatedTo()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_navigation.IsCancellationRequested)
        {
            _navigation.Dispose();
            _navigation = new();
        }
    }

    public override void OnNavigatedFrom()
    {
        if (_disposed) return;
        _navigation.Cancel();
        _busyVersion++;
        IsBusy = false;
    }

    private protected ClientSessionOperation BeginOperation(AppServices app, CancellationToken ct)
        => app.BeginOperation(ct, _navigation.Token);

    protected async Task RunSessionBusyAsync(Func<Task> action)
    {
        if (_disposed || _navigation.IsCancellationRequested || IsBusy) return;
        long version = ++_busyVersion;
        Error = null;
        IsBusy = true;
        try { await action(); }
        catch (OperationCanceledException) { }
        catch (Exception ex) { if (version == _busyVersion) Error = FriendlyError(ex); }
        finally { if (version == _busyVersion) IsBusy = false; }
    }

    public void Dispose()
    {
        if (_disposed) return;
        OnNavigatedFrom();
        _disposed = true;
        _navigation.Dispose();
    }
}
