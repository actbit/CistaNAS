namespace CistaNAS.Web.Services.Streams;

/// <summary>ボリューム I/O ガードをストリーム Dispose 時に解放するラッパー。</summary>
internal sealed class IoGuardReadStream(Stream inner, IDisposable ioGuard) : Stream
{
    public override bool CanRead => Volatile.Read(ref _disposed) == 0 && inner.CanRead;
    public override bool CanSeek => Volatile.Read(ref _disposed) == 0 && inner.CanSeek;
    public override bool CanWrite => false;
    public override long Length { get { ThrowIfDisposed(); return inner.Length; } }
    public override long Position
    {
        get { ThrowIfDisposed(); return inner.Position; }
        set { ThrowIfDisposed(); inner.Position = value; }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ThrowIfDisposed();
        return inner.Read(buffer, offset, count);
    }
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return inner.ReadAsync(buffer, cancellationToken);
    }
    public override long Seek(long offset, SeekOrigin origin) { ThrowIfDisposed(); return inner.Seek(offset, origin); }
    public override void Flush() { ThrowIfDisposed(); inner.Flush(); }

    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    private int _disposed;
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            // 内側 Dispose が例外を投げても I/O ガードは確実に解放する。
            // 解放漏れはボリュームのアンマウント（WaitForZeroAsync）を恒久スタックさせる。
            try { inner.Dispose(); }
            finally { ioGuard.Dispose(); }
        }
        base.Dispose(disposing);
    }
}
