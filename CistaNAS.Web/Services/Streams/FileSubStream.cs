namespace CistaNAS.Web.Services.Streams;

/// <summary>ボリュームストリームの部分範囲を読み取るラッパー。基礎ストリームは破棄しない。</summary>
/// <remarks>
/// FileSubStream（本型）は offset 基点・Seekable・streamLock で保護。
/// <see cref="SubStream"/> は残りバイト基点・baseStream を Dispose する別物。
/// </remarks>
internal sealed class FileSubStream(Stream baseStream, long offset, long length, SemaphoreSlim streamLock) : Stream
{
    private long _position;
    private volatile bool _disposed;

    public override bool CanRead => !_disposed;
    public override bool CanSeek => !_disposed;
    public override bool CanWrite => false;
    public override long Length { get { ObjectDisposedException.ThrowIf(_disposed, this); return length; } }
    public override long Position
    {
        get { ObjectDisposedException.ThrowIf(_disposed, this); return _position; }
        set
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (value < 0 || value > length) throw new ArgumentOutOfRangeException(nameof(value));
            _position = value;
        }
    }

    public override long Seek(long seekOffset, SeekOrigin origin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        long newPos = origin switch
        {
            SeekOrigin.Begin => seekOffset,
            SeekOrigin.Current => _position + seekOffset,
            SeekOrigin.End => length + seekOffset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        if (newPos < 0 || newPos > length) throw new ArgumentOutOfRangeException(nameof(seekOffset));
        _position = newPos;
        return newPos;
    }

    public override int Read(byte[] buffer, int bufOffset, int count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_position >= length) return 0;
        int toRead = (int)Math.Min(count, length - _position);
        if (toRead == 0) return 0;
        // 同期パスだが Dokan コールバック等の制約上 GetAwaiter().GetResult() を使用。
        // streamLock はボリューム単位で共有されるが、通常は短時間で解放されるためデッドロックリスクは低い。
        streamLock.WaitAsync(CancellationToken.None).GetAwaiter().GetResult();
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            baseStream.Position = offset + _position;
            int read = baseStream.Read(buffer, bufOffset, toRead);
            if (read == 0) throw new EndOfStreamException("保存済みファイルがカタログの長さより短くなっています。");
            _position += read;
            return read;
        }
        finally
        {
            streamLock.Release();
        }
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_position >= length) return 0;
        int toRead = (int)Math.Min(buffer.Length, length - _position);
        if (toRead == 0) return 0;
        await streamLock.WaitAsync(cancellationToken);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            baseStream.Position = offset + _position;
            int read = await baseStream.ReadAsync(buffer[..toRead], cancellationToken);
            if (read == 0) throw new EndOfStreamException("保存済みファイルがカタログの長さより短くなっています。");
            _position += read;
            return read;
        }
        finally
        {
            streamLock.Release();
        }
    }

    public override void Flush() => ObjectDisposedException.ThrowIf(_disposed, this);

    protected override void Dispose(bool disposing)
    {
        _disposed = true;
        base.Dispose(disposing);
    }

    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int writeOffset, int count) => throw new NotSupportedException();
}
