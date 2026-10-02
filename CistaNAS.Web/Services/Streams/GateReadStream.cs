namespace CistaNAS.Web.Services.Streams;

/// <summary>
/// ダウンロード中の読み取りゲートを保持するストリームラッパー。
/// Dispose 時にファイルゲートの読み取りロックを解放し、アップロード/削除を許可する。
/// </summary>
internal sealed class GateReadStream(Stream inner, IDisposable gateLock) : Stream
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
            // 内側 Dispose が例外を投げてもゲートロックは確実に解放する（例外安全性）。
            // 解放漏れは当該ファイルへのアップロード/削除の恒久スタベーションになる。
            try { inner.Dispose(); }
            finally { gateLock.Dispose(); }
        }
        base.Dispose(disposing);
    }
}
