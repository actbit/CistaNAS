using Avalonia.Media.Imaging;
using SkiaSharp;

namespace CistaNAS.Client.Services;

/// <summary>圧縮サイズだけでは防げない巨大画像を拒否し、長辺を制限してRAMへ復号する。</summary>
public static class ImagePreviewDecoder
{
    private const int MaxSide = 1600;
    private const long MaxPixels = 32L * 1024 * 1024;

    public static Bitmap Decode(byte[] bytes)
    {
        using var probe = new MemoryStream(bytes, writable: false);
        using var codec = SKCodec.Create(probe);
        if (codec is null || codec.Info.Width <= 0 || codec.Info.Height <= 0)
            throw new InvalidDataException("画像を読み取れませんでした。");
        int width = codec.Info.Width, height = codec.Info.Height;
        if ((long)width * height > MaxPixels)
            throw new InvalidDataException("画像の画素数が表示上限を超えています。");
        using var stream = new MemoryStream(bytes, writable: false);
        return width >= height
            ? Bitmap.DecodeToWidth(stream, Math.Min(width, MaxSide))
            : Bitmap.DecodeToHeight(stream, Math.Min(height, MaxSide));
    }
}
