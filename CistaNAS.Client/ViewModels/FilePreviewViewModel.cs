using System.Collections.ObjectModel;
using System.Text;
using Avalonia.Media.Imaging;
using CistaNAS.Client.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CistaNAS.Client.ViewModels;

public sealed partial class FilePreviewViewModel(IMountedFilePreviewService files) : ObservableObject, IDisposable
{
    private CancellationTokenSource? _read;
    private CancellationTokenSource? _listing;
    private long _listingVersion;
    private string _folder = "";
    private bool _disposed;
    [ObservableProperty] private ObservableCollection<PreviewEntry> _items = [];
    [ObservableProperty] private PreviewEntry? _selectedItem;
    [ObservableProperty] private string _location = "/";
    [ObservableProperty] private string _status = "画像・テキストを選択してください。";
    [ObservableProperty] private string _text = "";
    [ObservableProperty] private Bitmap? _image;

    public async Task RefreshAsync()
    {
        if (_disposed) return;
        long version = ++_listingVersion;
        string folder = _folder;
        _listing?.Cancel();
        _listing?.Dispose();
        _listing = new CancellationTokenSource();
        var ct = _listing.Token;
        ClearPreview();
        SelectedItem = null;
        Items.Clear();
        Status = "画像・テキストを選択してください。";
        try
        {
            var entries = await files.ListAsync(folder, ct);
            if (_disposed || ct.IsCancellationRequested || version != _listingVersion) return;
            Items = new(entries);
            Location = "/" + folder;
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { if (!_disposed && !ct.IsCancellationRequested && version == _listingVersion) Status = ex.Message; }
    }

    [RelayCommand] private async Task UpAsync()
    {
        _folder = Path.GetDirectoryName(_folder) ?? "";
        await RefreshAsync();
    }

    [RelayCommand] private async Task OpenAsync()
    {
        var item = SelectedItem;
        if (item is null || _disposed) return;
        if (item.IsFolder) { _folder = item.RelativePath; await RefreshAsync(); return; }
        ClearPreview();
        _read = new CancellationTokenSource();
        var ct = _read.Token;
        Status = "読み込み中...";
        try
        {
            using var bytes = await files.ReadAsync(item.RelativePath, ct);
            Bitmap? image = null;
            string text = "";
            await Task.Run(() =>
            {
                if (MountedFilePreviewService.IsImage(item.Name))
                {
                    image = ImagePreviewDecoder.Decode(bytes.Buffer);
                }
                else
                {
                    using var stream = new MemoryStream(bytes.Buffer, writable: false);
                    using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                    text = reader.ReadToEnd();
                }
            }, ct);
            if (ct.IsCancellationRequested || _disposed) { image?.Dispose(); return; }
            Image = image;
            Text = text;
            Status = item.Name;
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { if (!ct.IsCancellationRequested && !_disposed) Status = ex.Message; }
    }

    private void ClearPreview()
    {
        _read?.Cancel();
        _read?.Dispose();
        _read = null;
        Image?.Dispose();
        Image = null;
        Text = "";
    }
    public void Dispose()
    {
        _disposed = true;
        _listing?.Cancel();
        _listing?.Dispose();
        _listing = null;
        ClearPreview();
        Items.Clear();
    }
}
