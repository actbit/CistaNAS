using Avalonia;
using CistaNAS.Client.Services;
using SkiaSharp;

namespace CistaNAS.Tests;

public sealed class ImagePreviewDecoderTests
{
    static ImagePreviewDecoderTests() => AppBuilder.Configure<Application>().UsePlatformDetect().SetupWithoutStarting();

    [Theory]
    [InlineData(8, 20, 8, 20)]
    [InlineData(100, 8000, 20, 1600)]
    [InlineData(8000, 100, 1600, 20)]
    public void PreviewNeverUpscalesAndBoundsBothOrientations(int width, int height, int expectedWidth, int expectedHeight)
    {
        using var source = new SKBitmap(width, height);
        source.Erase(SKColors.Blue);
        using var encoded = source.Encode(SKEncodedImageFormat.Png, 100);
        using var image = ImagePreviewDecoder.Decode(encoded.ToArray());
        Assert.Equal(new PixelSize(expectedWidth, expectedHeight), image.PixelSize);
    }

    [Fact]
    public void SmallCompressedImageWithExcessivePixels_IsRejected()
    {
        // A PNG header is enough to declare a huge raster; no large test allocation.
        using var source = new SKBitmap(1, 1);
        using var encoded = source.Encode(SKEncodedImageFormat.Png, 100);
        byte[] png = encoded.ToArray();
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(png.AsSpan(16, 4), 10000);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(png.AsSpan(20, 4), 5000);
        uint crc = 0xffffffff;
        foreach (byte b in png.AsSpan(12, 17))
        {
            crc ^= b;
            for (int i = 0; i < 8; i++) crc = (crc >> 1) ^ ((crc & 1) != 0 ? 0xedb88320u : 0);
        }
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(png.AsSpan(29, 4), ~crc);
        var error = Assert.Throws<InvalidDataException>(() => ImagePreviewDecoder.Decode(png));
        Assert.Contains("画素数", error.Message);
    }
}
