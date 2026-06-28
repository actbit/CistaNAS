using CistaNAS.Web.Services.Streams;

namespace CistaNAS.Tests;

/// <summary>
/// Stream ラッパーの Dispose 例外安全性を検証。
/// 内側 Stream の Dispose が例外を投げても、保持するロック/ガードが確実に解放されること。
/// </summary>
public class StreamDisposeTests
{
    /// <summary>Dispose で例外を投げるモック Stream。</summary>
    private sealed class ThrowOnDisposeStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => 0;
        public override long Position { get; set; }
        public override int Read(byte[] buffer, int offset, int count) => 0;
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => 0;
        public override void SetLength(long value) { }
        public override void Write(byte[] buffer, int offset, int count) { }
        protected override void Dispose(bool disposing) =>
            throw new InvalidOperationException("simulated dispose failure");
    }

    private sealed class FlagDisposable : IDisposable
    {
        public bool Disposed;
        public void Dispose() => Disposed = true;
    }

    [Fact]
    public void GateReadStream_InnerDisposeThrows_StillReleasesGate()
    {
        var inner = new ThrowOnDisposeStream();
        var gateLock = new FlagDisposable();
        var gate = new GateReadStream(inner, gateLock);

        Assert.Throws<InvalidOperationException>(() => gate.Dispose());
        Assert.True(gateLock.Disposed, "内側例外時もゲートロックは解放されるべき");
    }

    [Fact]
    public void IoGuardReadStream_InnerDisposeThrows_StillReleasesGuard()
    {
        var inner = new ThrowOnDisposeStream();
        var guard = new FlagDisposable();
        var stream = new IoGuardReadStream(inner, guard);

        Assert.Throws<InvalidOperationException>(() => stream.Dispose());
        Assert.True(guard.Disposed, "内側例外時も I/O ガードは解放されるべき");
    }
}
