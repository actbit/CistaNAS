using CommunityToolkit.Mvvm.ComponentModel;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>画像ビューア。復号済みバイト列を View 側で Bitmap 化して表示する。</summary>
public sealed partial class ImageViewerViewModel(AppServices app, FileBrowserViewModel browser, FileItem item) : BusyViewModelBase
{
    [ObservableProperty]
    private byte[]? _imageData;

    public string FileName => item.Name;

    public override string Title => item.Name;

    public override async void OnNavigatedTo() => await RunBusyAsync(async () =>
    {
        if (browser.IsE2ee && item.E2eeEntry is not null)
        {
            using MemoryStream ms = await app.Transfer.OpenDecryptedAsync(browser.VolumeName, item.E2eeEntry);
            ImageData = ms.ToArray();
        }
        else
        {
            ImageData = await app.Session.Api.DownloadFileAsync(browser.VolumeName, item.FullPath);
        }
    });
}
