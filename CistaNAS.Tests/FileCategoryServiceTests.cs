using CistaNAS.Mobile.Core.Security;
using CistaNAS.Mobile.Core.Services;
using Xunit;

namespace CistaNAS.Tests;

public class FileCategoryServiceTests
{
    [Theory]
    [InlineData("photo.jpg", FileCategory.Image)]
    [InlineData("photo.HEIC", FileCategory.Image)]
    [InlineData("movie.mp4", FileCategory.Video)]
    [InlineData("song.flac", FileCategory.Audio)]
    [InlineData("notes.md", FileCategory.Text)]
    [InlineData("data.json", FileCategory.Text)]
    [InlineData("archive.zip", FileCategory.Other)]
    [InlineData("noext", FileCategory.Other)]
    public void カテゴリ判定(string name, FileCategory expected)
        => Assert.Equal(expected, FileCategoryService.Categorize(name));

    [Theory]
    [InlineData("a.jpg", "image/jpeg")]
    [InlineData("a.mp4", "video/mp4")]
    [InlineData("a.pdf", "application/pdf")]
    [InlineData("a.unknown", "application/octet-stream")]
    public void MIME判定(string name, string expected)
        => Assert.Equal(expected, FileCategoryService.GetMimeType(name));

    [Theory]
    [InlineData(512, "512 B")]
    [InlineData(2048, "2 KB")]
    [InlineData(5 * 1024 * 1024, "5 MB")]
    public void サイズ整形(long bytes, string expected)
        => Assert.Equal(expected, FileCategoryService.FormatSize(bytes));
}

public class MobileSecureBufferTests
{
    [Fact]
    public void 解放時にゼロクリアされる()
    {
        byte[] key = [1, 2, 3, 4, 5];
        var buffer = new SecureBuffer(key);
        Assert.Equal(key, buffer.Data);

        buffer.Dispose();
        // 内部バッファがゼロクリアされていること
        byte[]? raw = buffer.PeekRawForTest();
        Assert.NotNull(raw);
        Assert.All(raw!, b => Assert.Equal(0, b));
        Assert.Throws<InvalidOperationException>(() => buffer.Data);
    }

    [Fact]
    public void 解放は冪等()
    {
        var buffer = new SecureBuffer(16);
        buffer.Dispose();
        buffer.Dispose();
    }

    [Fact]
    public void 初期コピー元の変更は反映されない()
    {
        byte[] key = [1, 2, 3];
        var buffer = new SecureBuffer(key);
        key[0] = 0xFF;
        Assert.Equal(1, buffer.Data[0]);
        buffer.Dispose();
    }
}

public class EcdhKeyManagerTests
{
    [Fact]
    public void SEC1秘密鍵からraw公開鍵を導出できる()
    {
        (byte[] publicKey, byte[] privateKey) = CistaNAS.Shared.Crypto.E2eeCrypto.GenerateEcdhKeyPair();
        byte[] derived = CistaNAS.Mobile.Core.Services.EcdhKeyManager.GetRawPublicKey(privateKey);
        Assert.Equal(publicKey, derived);
        Assert.Equal(65, derived.Length);
        Assert.Equal(0x04, derived[0]);
    }
}
