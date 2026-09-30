using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>テキストドキュメント (TXT/MD/JSON/XML/CSV 等) のビューア。</summary>
public sealed partial class TextViewerViewModel(AppServices app, FileBrowserViewModel browser, FileItem item)
    : BufferedViewerViewModel(app, browser, item, BufferedFileService.TextLimit)
{
    [ObservableProperty]
    private string _content = "";

    protected override bool ShowContent(byte[] bytes)
    {
        // BOM 検出付きでデコード (無ければ UTF-8)
        using var stream = new MemoryStream(bytes, writable: false);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        Content = reader.ReadToEnd();
        return false;
    }

    protected override void ClearContent() => Content = "";
}
