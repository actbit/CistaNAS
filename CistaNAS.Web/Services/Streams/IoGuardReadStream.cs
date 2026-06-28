namespace CistaNAS.Web.Services.Streams;

/// <summary>ボリューム I/O ガードをストリーム Dispose 時に解放するラッパー。</summary>
internal sealed class IoGuardReadStream(Stream inner, IDisposable ioGuard) : Stream
{
    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => inner.CanSeek;
    public override bool CanWrite => false;
    public override long Length => inner.Length;
    public override long Position { get => inner.Position; set => inner.Position = value; }

    public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => inner.ReadAsync(buffer, cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
    public override void Flush() => inner.Flush();

    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    private bool _disposed;

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            // 内側 Dispose が例外を投げても I/O ガードは確実に解放する。
            // 解放漏れはボリュームのアンマウント（WaitForZeroAsync）を恒久スタックさせる。
            try { inner.Dispose(); }
            finally { ioGuard.Dispose(); }
        }
        base.Dispose(disposing);
    }
}
