using CommunityToolkit.Mvvm.ComponentModel;
using System.Security.Cryptography;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>画像ビューア。復号済みバイト列を View 側で Bitmap 化して表示する。</summary>
public sealed partial class ImageViewerViewModel(AppServices app, FileBrowserViewModel browser, FileItem item)
    : BufferedViewerViewModel(app, browser, item, BufferedFileService.ImageLimit)
{
    [ObservableProperty]
    private byte[]? _imageData;

    protected override bool ShowContent(byte[] bytes)
    {
        ImageData = bytes;
        return true;
    }

    protected override void ClearContent()
    {
        if (ImageData is not null) CryptographicOperations.ZeroMemory(ImageData);
        ImageData = null;
    }
}
