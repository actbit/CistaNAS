using CistaNAS.Web.Services.Streams;

namespace CistaNAS.Tests;

public sealed class BoundedDownloadIntegrityTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task TruncatedBackingStream_ThrowsAtUnexpectedEnd(bool seekable, bool asyncRead)
    {
        using var backing = new MemoryStream(new byte[] { 1, 2, 3 });
        using var streamLock = new SemaphoreSlim(1, 1);
        using Stream stream = seekable
            ? new FileSubStream(backing, 0, 5, streamLock)
            : new SubStream(backing, 5);
        byte[] buffer = new byte[5];
        int read = asyncRead ? await stream.ReadAsync(buffer.AsMemory()) : stream.Read(buffer, 0, 5);
        Assert.Equal(3, read);

        // 空のバッファはストレージを読まず、途中でも正常に 0 を返す。
        Assert.Equal(0, asyncRead ? await stream.ReadAsync(Memory<byte>.Empty) : stream.Read([], 0, 0));
        if (asyncRead)
            await Assert.ThrowsAsync<EndOfStreamException>(() => stream.ReadAsync(buffer.AsMemory()).AsTask());
        else
            Assert.Throws<EndOfStreamException>(() => stream.Read(buffer, 0, buffer.Length));
        Assert.Equal(3, stream.Position);
        Assert.Equal(1, streamLock.CurrentCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShortReadsWithinDeclaredLength_AreAllowed(bool seekable)
    {
        using var backing = new OneByteReadStream(new byte[] { 1, 2, 3 });
        using var streamLock = new SemaphoreSlim(1, 1);
        using Stream stream = seekable
            ? new FileSubStream(backing, 0, 3, streamLock)
            : new SubStream(backing, 3);
        byte[] buffer = new byte[3];
        await stream.ReadExactlyAsync(buffer);
        Assert.Equal(new byte[] { 1, 2, 3 }, buffer);
        Assert.Equal(0, await stream.ReadAsync(buffer.AsMemory()));
        Assert.Equal(0, stream.Read(buffer, 0, buffer.Length));
    }

    private sealed class OneByteReadStream(byte[] data) : MemoryStream(data)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => base.ReadAsync(buffer[..Math.Min(1, buffer.Length)], cancellationToken);
    }
}
