using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>動画・音声・PDFをアプリ内で表示する。復号ファイルを作成しない。</summary>
public sealed partial class StreamingViewerViewModel(AppServices app, FileBrowserViewModel browser, FileItem item)
    : BusyViewModelBase, IDisposable
{
    private CancellationTokenSource? _cancellation;

    [ObservableProperty]
    private string _status = "準備中...";
    public string FileName => item.Name;
    public override string Title => item.Name;

    public override async void OnNavigatedTo() => await RunBusyAsync(OpenAsync);
    [RelayCommand]
    private Task RetryAsync() => RunBusyAsync(OpenAsync);

    private async Task OpenAsync()
    {
        _cancellation?.Cancel();
        _cancellation?.Dispose();
        _cancellation = CancellationTokenSource.CreateLinkedTokenSource(app.SessionCancellation);
        var ct = _cancellation.Token;
        Status = "表示を準備中...";
        ReadOnlyFileContent? content = null;
        try
        {
            if (browser.IsE2ee)
                content = await app.StreamingFiles.OpenE2eeFileAsync(browser.VolumeName, item.Name,
                    item.E2eeEntry ?? throw new InvalidDataException("ファイル情報がありません。"), ct);
            else
                content = app.StreamingFiles.OpenServerFile(browser.VolumeName, item.FullPath,
                    item.ServerMeta ?? throw new InvalidDataException("ファイル情報がありません。"), ct);
            ct.ThrowIfCancellationRequested();
            if (!await app.Viewer.LaunchAsync(content))
            {
                Status = "この形式のアプリ内表示には対応していません。";
                return;
            }
            content = null; // 表示画面が所有し、閉じる時に消去する。
            ct.ThrowIfCancellationRequested();
            Status = "アプリ内Viewerで表示しました。";
        }
        finally { content?.Dispose(); }
    }

    public override void OnNavigatedFrom() => _cancellation?.Cancel();
    public void Dispose()
    {
        _cancellation?.Cancel();
        _cancellation?.Dispose();
        _cancellation = null;
    }
}
