using CistaNAS.Client.Services;

namespace CistaNAS.Tests;

public sealed class MountedFilePreviewServiceTests
{
    [Theory]
    [InlineData("")]
    [InlineData("C:\\Users")]
    [InlineData(".")]
    public void InvalidMountPoint_DoesNotFallBackToLocalDisk(string mount) =>
        Assert.Throws<ArgumentException>(() => new MountedFilePreviewService(mount));

    [Theory]
    [InlineData("../secret.txt")]
    [InlineData("..\\secret.txt")]
    [InlineData("C:\\secret.txt")]
    [InlineData("\\secret.txt")]
    [InlineData("secret.txt:stream")]
    public void PathsOutsideMount_AreRejected(string path) =>
        Assert.Throws<ArgumentException>(() => new MountedFilePreviewService("X:\\").Resolve(path));

    [Fact]
    public async Task PreviewReadsOnlySourceStream_AndZerosOwnedBufferOnClose()
    {
        var source = new MemoryStream(new byte[] { 1, 2, 3 }, writable: false);
        var service = new MountedFilePreviewService("X:\\", path => { Assert.Equal("X:\\docs\\readme.txt", path); return source; });
        var preview = await service.ReadAsync("docs/readme.txt", default);
        byte[] bytes = preview.Buffer;
        Assert.Equal(new byte[] { 1, 2, 3 }, bytes);
        Assert.False(source.CanRead);
        preview.Dispose();
        Assert.All(bytes, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task OversizedAndUnsupportedFiles_AreRejectedBeforeReading()
    {
        var service = new MountedFilePreviewService("X:\\", _ => new OversizedStream());
        await Assert.ThrowsAsync<IOException>(() => service.ReadAsync("huge.txt", default));
        await Assert.ThrowsAsync<NotSupportedException>(() => service.ReadAsync("clip.mp4", default));
    }

    [Fact]
    public async Task CancelledPreview_DoesNotOpenSource()
    {
        var service = new MountedFilePreviewService("X:\\", _ => throw new InvalidOperationException());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.ReadAsync("secret.txt", new CancellationToken(true)));
    }

    private sealed class OversizedStream : MemoryStream
    {
        public override long Length => MountedFilePreviewService.TextLimit + 1;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => throw new InvalidOperationException();
    }
}
