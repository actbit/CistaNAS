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

    private async Task TransferAndLaunchAsync()
    {
        ProgressPercent = 0;
        Status = "ダウンロード中...";
        var progress = new Progress<double>(p => ProgressPercent = p);

        string cacheName = MakeSafeCacheName();
        await using (Stream output = app.FileCache.OpenWrite(cacheName))
        {
            if (browser.IsE2ee && item.E2eeEntry is not null)
            {
                await app.Transfer.DownloadAsync(browser.VolumeName, item.E2eeEntry, output, progress);
            }
            else
            {
                await using Stream source = await app.Session.Api.DownloadFileStreamAsync(browser.VolumeName, item.FullPath);
                await source.CopyToAsync(output);
            }
        }

        Status = "アプリを起動中...";
        bool launched = await app.ExternalViewer.LaunchAsync(
            app.FileCache.GetPath(cacheName),
            FileCategoryService.GetMimeType(FileName));
        Status = launched ? "外部アプリで表示しました。" : "このファイルを開けるアプリが見つかりません。";
    }

    /// <summary>キャッシュファイル名の衝突を避けるためボリューム名とパスを含める。</summary>
    private string MakeSafeCacheName()
    {
        string raw = $"{browser.VolumeName}_{browser.CurrentPath}_{FileName}";
        foreach (char c in Path.GetInvalidFileNameChars())
            raw = raw.Replace(c, '_');
        return raw;
    }
}
