using System.Collections.ObjectModel;
using System.Text;
using Avalonia.Media.Imaging;
using CistaNAS.Client.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CistaNAS.Client.ViewModels;

public sealed partial class FilePreviewViewModel(MountedFilePreviewService files) : ObservableObject, IDisposable
{
    private CancellationTokenSource? _read;
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
        ClearPreview();
        Status = "画像・テキストを選択してください。";
        try
        {
            var entries = await Task.Run(() => files.List(_folder));
            if (_disposed) return;
            Items = new(entries);
            Location = "/" + _folder;
        }
        catch (Exception ex) { if (!_disposed) Status = ex.Message; }
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
                    using var stream = new MemoryStream(bytes.Buffer, writable: false);
                    image = Bitmap.DecodeToWidth(stream, 1600);
                }
                else text = Encoding.UTF8.GetString(bytes.Buffer);
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
    public void Dispose() { _disposed = true; ClearPreview(); Items.Clear(); }
}
