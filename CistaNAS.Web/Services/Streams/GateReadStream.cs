namespace CistaNAS.Web.Services.Streams;

/// <summary>
/// ダウンロード中の読み取りゲートを保持するストリームラッパー。
/// Dispose 時にファイルゲートの読み取りロックを解放し、アップロード/削除を許可する。
/// </summary>
internal sealed class GateReadStream(Stream inner, IDisposable gateLock) : Stream
{
    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => inner.CanSeek;
    public override bool CanWrite => false;
    public override long Length => inner.Length;
    public override long Position
    {
        get => inner.Position;
        set => inner.Position = value;
    }

    public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => inner.ReadAsync(buffer, cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
    public override void Flush() => inner.Flush();

    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    private bool _lockReleased;

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            inner.Dispose();
            if (!_lockReleased)
            {
                gateLock.Dispose();
                _lockReleased = true;
            }
        }
        base.Dispose(disposing);
    }
}
