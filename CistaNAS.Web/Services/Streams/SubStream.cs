namespace CistaNAS.Web.Services.Streams;

/// <summary>
/// 部分読み取り用 Stream ラッパー（残りバイト基点・Dispose で baseStream を破棄）。
/// <see cref="FileSubStream"/>（offset 基点・Seekable・streamLock 保護）とは別物。
/// </summary>
internal sealed class SubStream(Stream baseStream, long length) : Stream
{
    private readonly long _length = length;
    private long _remaining = length;
    private bool _disposed;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _length;
    public override long Position { get => _length - _remaining; set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_remaining <= 0) return 0;
        int toRead = (int)Math.Min(count, _remaining);
        int read = baseStream.Read(buffer, offset, toRead);
        _remaining -= read;
        return read;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_remaining <= 0) return 0;
        int toRead = (int)Math.Min(buffer.Length, _remaining);
        int read = await baseStream.ReadAsync(buffer[..toRead], cancellationToken);
        _remaining -= read;
        return read;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            baseStream.Dispose();
        }
        base.Dispose(disposing);
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
