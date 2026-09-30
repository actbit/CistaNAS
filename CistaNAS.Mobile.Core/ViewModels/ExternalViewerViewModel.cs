using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>
/// 外部アプリ委譲ビューア (動画・音声・PDF 等)。
/// 復号 → キャッシュファイルへ書き出し → IExternalViewerLauncher で ACTION_VIEW。
/// </summary>
public sealed partial class ExternalViewerViewModel(AppServices app, FileBrowserViewModel browser, FileItem item) : BusyViewModelBase
{
    private CancellationTokenSource? _transferCancellation;

    [ObservableProperty]
    private double _progressPercent;

    [ObservableProperty]
    private string _status = "準備中...";

    public string FileName => item.Name;

    public override string Title => item.Name;

    public override async void OnNavigatedTo()
    {
        await RunBusyAsync(TransferAndLaunchAsync);
    }

    [RelayCommand]
    private Task RetryAsync(CancellationToken ct) => RunBusyAsync(TransferAndLaunchAsync);

    public override void OnNavigatedFrom() => _transferCancellation?.Cancel();

    private async Task TransferAndLaunchAsync()
    {
        ProgressPercent = 0;
        Status = "ダウンロード中...";
        var progress = new Progress<double>(p => ProgressPercent = p);

        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(app.SessionCancellation);
        _transferCancellation = cancellation;
        CancellationToken ct = cancellation.Token;
        string cacheName = MakeSafeCacheName();
        bool keepCache = false;
        try
        {
            ct.ThrowIfCancellationRequested();
            await using (Stream output = app.FileCache.OpenWrite(cacheName))
            {
                if (browser.IsE2ee && item.E2eeEntry is not null)
                {
                    await app.Transfer.DownloadAsync(browser.VolumeName, item.E2eeEntry, output, progress, ct);
                }
                else
                {
                    await using Stream source = await app.Session.Api.DownloadFileStreamAsync(browser.VolumeName, item.FullPath, ct);
                    await source.CopyToAsync(output, ct);
                }
            }

            ct.ThrowIfCancellationRequested();
            Status = "アプリを起動中...";
            bool launched = await app.ExternalViewer.LaunchAsync(
                app.FileCache.GetPath(cacheName),
                FileCategoryService.GetMimeType(FileName));
            ct.ThrowIfCancellationRequested();
            keepCache = launched;
            Status = launched ? "外部アプリで表示しました。" : "このファイルを開けるアプリが見つかりません。";
        }
        finally
        {
            _transferCancellation = null;
            if (!keepCache) app.FileCache.Delete(cacheName);
        }
    }

    /// <summary>既に外部アプリへ渡した URI を別ファイルの内容に使い回さない。</summary>
    private string MakeSafeCacheName()
    {
        string extension = Path.GetExtension(FileName);
        if (extension.Length > 20 || extension.Any(c => c != '.' && !char.IsAsciiLetterOrDigit(c)))
            extension = "";
        return Guid.NewGuid().ToString("N") + extension;
    }
}
