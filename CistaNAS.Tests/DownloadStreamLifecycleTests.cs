using CistaNAS.Web.Services.Streams;

namespace CistaNAS.Tests;

public sealed class DownloadStreamLifecycleTests
{
    [Theory]
    [InlineData("gate")]
    [InlineData("io")]
    [InlineData("file")]
    [InlineData("sub")]
    public async Task DisposedDownload_CannotReadReusedBackingStorage(string kind)
    {
        using var backing = new NonClosingStream();
        using var streamLock = new SemaphoreSlim(1, 1);
        var guard = new CountingGuard();
        Stream stream = kind switch
        {
            "gate" => new GateReadStream(backing, guard),
            "io" => new IoGuardReadStream(backing, guard),
            "file" => new FileSubStream(backing, 0, 3, streamLock),
            _ => new SubStream(backing, 3),
        };
        stream.Dispose();
        backing.Position = 0;
        backing.Write(new byte[] { 9, 9, 9 });
        backing.Position = 0;

        Assert.Throws<ObjectDisposedException>(() => stream.Read(new byte[3], 0, 3));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => stream.ReadAsync(new byte[3].AsMemory()).AsTask());
        Assert.False(stream.CanRead);
        Assert.False(stream.CanSeek);
        Assert.Equal(0, backing.Position);
        if (kind is "gate" or "io") Assert.Equal(1, guard.DisposeCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FailedInnerDispose_StillClosesWrapperAndReleasesGuardExactlyOnce(bool io)
    {
        using var backing = new NonClosingStream { ThrowOnDispose = true };
        var guard = new CountingGuard();
        Stream stream = io ? new IoGuardReadStream(backing, guard) : new GateReadStream(backing, guard);
        Assert.Throws<IOException>(() => stream.Dispose());
        Assert.Equal(1, guard.DisposeCount);
        stream.Dispose();
        Assert.Equal(1, backing.DisposeCount);
        Assert.Equal(1, guard.DisposeCount);
        Assert.Throws<ObjectDisposedException>(() => stream.ReadByte());
        backing.ThrowOnDispose = false;
    }

    [Fact]
    public async Task DisposedQueuedFileRead_DoesNotTouchBackingStream()
    {
        using var backing = new NonClosingStream();
        using var streamLock = new SemaphoreSlim(0, 1);
        var stream = new FileSubStream(backing, 0, 3, streamLock);
        Task<int> read = stream.ReadAsync(new byte[3].AsMemory()).AsTask();
        stream.Dispose();
        streamLock.Release();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => read.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(0, backing.Position);
        Assert.Equal(1, streamLock.CurrentCount);
    }

    private sealed class CountingGuard : IDisposable
    {
        public int DisposeCount { get; private set; }
        public void Dispose() => DisposeCount++;
    }

    private sealed class NonClosingStream() : MemoryStream(new byte[] { 1, 2, 3 })
    {
        public bool ThrowOnDispose { get; set; }
        public int DisposeCount { get; private set; }
        protected override void Dispose(bool disposing)
        {
            DisposeCount++;
            if (ThrowOnDispose) throw new IOException("Simulated disposal failure");
        }
    }
}
