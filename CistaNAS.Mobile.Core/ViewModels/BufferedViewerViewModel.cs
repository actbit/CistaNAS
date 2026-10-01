using System.Security.Cryptography;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>戻る・ログアウトで読み取りを止め、遅れた結果を破棄するRAM表示画面。</summary>
public abstract class BufferedViewerViewModel(AppServices app, FileBrowserViewModel browser, FileItem item, int limit)
    : BusyViewModelBase, IDisposable
{
    private CancellationTokenSource? _load;
    private CancellationTokenRegistration _clearOnCancel;
    private long _version;
    private bool _disposed;
    public string FileName => item.Name;
    public override string Title => item.Name;

    public override async void OnNavigatedTo()
    {
        if (_disposed) return;
        CancelLoad();
        long version = ++_version;
        _load = CancellationTokenSource.CreateLinkedTokenSource(app.SessionCancellation);
        var ct = _load.Token;
        _clearOnCancel = ct.Register(ClearContent);
        IsBusy = true;
        Error = null;
        try
        {
            byte[] bytes = await app.BufferedFiles.ReadAsync(browser.VolumeName, item.Name, item.FullPath,
                browser.IsE2ee, item.ServerMeta, item.E2eeEntry, limit, ct);
            bool transferred = false;
            try
            {
                ct.ThrowIfCancellationRequested();
                if (_disposed || version != _version) return;
                transferred = ShowContent(bytes);
                // Cancellation can run on the HTTP thread between the check and
                // publication. Never leave content published after that clear.
                if (ct.IsCancellationRequested)
                {
                    CryptographicOperations.ZeroMemory(bytes);
                    if (version == _version) ClearContent();
                }
            }
            finally { if (!transferred) CryptographicOperations.ZeroMemory(bytes); }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex) { if (!_disposed && !ct.IsCancellationRequested && version == _version) Error = FriendlyError(ex); }
        finally { if (version == _version) IsBusy = false; }
    }

    /// <returns>バッファの所有権を画面へ移した場合はtrue。</returns>
    protected abstract bool ShowContent(byte[] bytes);
    protected abstract void ClearContent();

    private void CancelLoad()
    {
        _load?.Cancel();
        _clearOnCancel.Dispose();
        _load?.Dispose();
        _load = null;
        ClearContent();
    }

    public override void OnNavigatedFrom()
    {
        ++_version;
        CancelLoad();
        IsBusy = false;
    }

    public void Dispose() { if (_disposed) return; _disposed = true; OnNavigatedFrom(); }
}
