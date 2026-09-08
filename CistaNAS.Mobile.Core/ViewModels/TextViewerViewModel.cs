using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>テキストドキュメント (TXT/MD/JSON/XML/CSV 等) のビューア。</summary>
public sealed partial class TextViewerViewModel(AppServices app, FileBrowserViewModel browser, FileItem item) : BusyViewModelBase
{
    [ObservableProperty]
    private string _content = "";

    public string FileName => item.Name;

    public override string Title => item.Name;

    public override async void OnNavigatedTo() => await RunBusyAsync(async () =>
    {
        byte[] bytes;
        if (browser.IsE2ee && item.E2eeEntry is not null)
        {
            using MemoryStream ms = await app.Transfer.OpenDecryptedAsync(browser.VolumeName, item.E2eeEntry);
            bytes = ms.ToArray();
        }
        else
        {
            bytes = await app.Session.Api.DownloadFileAsync(browser.VolumeName, item.FullPath);
        }
        // BOM 検出付きでデコード (無ければ UTF-8)
        using var reader = new StreamReader(new MemoryStream(bytes), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        Content = await reader.ReadToEndAsync();
    });
}
