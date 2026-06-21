namespace CistaNAS.Web.Services.Streams;

/// <summary>ボリュームストリームの部分範囲を読み取るラッパー。基礎ストリームは破棄しない。</summary>
/// <remarks>
/// FileSubStream（本型）は offset 基点・Seekable・streamLock で保護。
/// <see cref="SubStream"/> は残りバイト基点・baseStream を Dispose する別物。
/// </remarks>
internal sealed class FileSubStream(Stream baseStream, long offset, long length, SemaphoreSlim streamLock) : Stream
{
    private long _position;

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => length;
    public override long Position
    {
        get => _position;
        set
        {
            if (value < 0 || value > length) throw new ArgumentOutOfRangeException(nameof(value));
            _position = value;
        }
    }

    public override long Seek(long seekOffset, SeekOrigin origin)
    {
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
        if (_position >= length) return 0;
        int toRead = (int)Math.Min(count, length - _position);
        // 同期パスだが Dokan コールバック等の制約上 GetAwaiter().GetResult() を使用。
        // streamLock はボリューム単位で共有されるが、通常は短時間で解放されるためデッドロックリスクは低い。
        streamLock.WaitAsync(CancellationToken.None).GetAwaiter().GetResult();
        try
        {
            baseStream.Position = offset + _position;
            int read = baseStream.Read(buffer, bufOffset, toRead);
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
        if (_position >= length) return 0;
        int toRead = (int)Math.Min(buffer.Length, length - _position);
        await streamLock.WaitAsync(cancellationToken);
        try
        {
            baseStream.Position = offset + _position;
            int read = await baseStream.ReadAsync(buffer[..toRead], cancellationToken);
            _position += read;
            return read;
        }
        finally
        {
            streamLock.Release();
        }
    }

    public override void Flush() { }

    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int writeOffset, int count) => throw new NotSupportedException();
}
