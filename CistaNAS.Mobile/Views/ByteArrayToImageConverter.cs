using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media.Imaging;

namespace CistaNAS.Mobile.Views;

/// <summary>byte[] (画像データ) を IImage (Bitmap) に変換するコンバーター。</summary>
public sealed class ByteArrayToImageConverter : IValueConverter
{
    public static readonly ByteArrayToImageConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not byte[] bytes || bytes.Length == 0)
            return null;
        try
        {
            return new Bitmap(new MemoryStream(bytes));
        }
        catch (Exception)
        {
            return null;
        }
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
