using Avalonia.Controls;
using Avalonia.Interactivity;

namespace CistaNAS.Mobile.Views;

/// <summary>画像ビューア。ズームは Image の Width を基準の倍率で変更する。</summary>
public partial class ImageViewerView : UserControl
{
    private const double BaseWidth = 800;
    private double _zoom = 1.0;

    public ImageViewerView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => SetZoom(1.0);
    }

    private void OnZoomIn(object? sender, RoutedEventArgs e) => SetZoom(_zoom * 1.25);

    private void OnZoomOut(object? sender, RoutedEventArgs e) => SetZoom(_zoom / 1.25);

    private void SetZoom(double zoom)
    {
        _zoom = Math.Clamp(zoom, 0.25, 8.0);
        ViewerImage.Width = BaseWidth * _zoom;
    }
}
