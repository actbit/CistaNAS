using System.ComponentModel;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using CistaNAS.Client.Services;
using CistaNAS.Mobile.Core.ViewModels;

namespace CistaNAS.Mobile.Views;

/// <summary>画像ビューア。ズームは Image の Width を基準の倍率で変更する。</summary>
public partial class ImageViewerView : UserControl
{
    private const double BaseWidth = 800;
    private double _zoom = 1.0;
    private ImageViewerViewModel? _viewModel;
    private Bitmap? _bitmap;

    public ImageViewerView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => { BindViewModel(); SetZoom(1.0); };
        AttachedToVisualTree += (_, _) => BindViewModel();
        DetachedFromVisualTree += (_, _) =>
        {
            if (_viewModel is not null) _viewModel.PropertyChanged -= OnContentChanged;
            _viewModel = null;
            ClearBitmap();
        };
    }

    private void BindViewModel()
    {
        if (_viewModel is not null) _viewModel.PropertyChanged -= OnContentChanged;
        _viewModel = DataContext as ImageViewerViewModel;
        if (_viewModel is not null) _viewModel.PropertyChanged += OnContentChanged;
        UpdateImage();
    }

    private void OnContentChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(ImageViewerViewModel.ImageData)) return;
        if (Dispatcher.UIThread.CheckAccess()) UpdateImage();
        else Dispatcher.UIThread.Post(UpdateImage);
    }

    private void ClearBitmap()
    {
        ViewerImage.Source = null;
        _bitmap?.Dispose();
        _bitmap = null;
    }

    private void UpdateImage()
    {
        ClearBitmap();
        if (_viewModel?.ImageData is not { Length: > 0 } bytes) return;
        try
        {
            _bitmap = ImagePreviewDecoder.Decode(bytes);
            ViewerImage.Source = _bitmap;
        }
        catch (Exception ex) { _viewModel.Error = ex.Message; }
    }

    private void OnZoomIn(object? sender, RoutedEventArgs e) => SetZoom(_zoom * 1.25);

    private void OnZoomOut(object? sender, RoutedEventArgs e) => SetZoom(_zoom / 1.25);

    private void SetZoom(double zoom)
    {
        _zoom = Math.Clamp(zoom, 0.25, 8.0);
        ViewerImage.Width = BaseWidth * _zoom;
    }
}
