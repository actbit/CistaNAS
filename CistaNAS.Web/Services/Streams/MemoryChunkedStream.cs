using CistaNAS.Web.Storage;

namespace CistaNAS.Web.Services.Streams;

/// <summary>非暗号化チャンクストアから遅延取得する Seekable ストリーム。</summary>
internal sealed class MemoryChunkedStream : Stream
{
    private readonly IChunkStore _chunkStore;
    private readonly string _volumeName;
    private readonly string _objectId;
    private readonly IReadOnlyList<int> _chunkSizes;
    private readonly long[] _cumulativeSizes;
    private readonly long _totalLength;

    private long _position;
    private volatile int _cachedChunkIndex = -1;
    private byte[]? _cachedData;
    private bool _disposed;

    public MemoryChunkedStream(
        IChunkStore chunkStore,
        string volumeName,
        string objectId,
        IReadOnlyList<int> chunkSizes)
    {
        _chunkStore = chunkStore;
        _volumeName = volumeName;
        _objectId = objectId;
        _chunkSizes = chunkSizes;

        _cumulativeSizes = new long[chunkSizes.Count];
        long acc = 0;
        for (int i = 0; i < chunkSizes.Count; i++)
        {
            _cumulativeSizes[i] = acc;
            acc += chunkSizes[i];
        }
        _totalLength = acc;
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _totalLength;

    public override long Position
    {
        get => _position;
        set
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, _totalLength);
            _position = value;
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_position >= _totalLength) return 0;
        count = (int)Math.Min(count, _totalLength - _position);
        int totalRead = 0;

        while (count > 0)
        {
            (int chunkIdx, int offsetInChunk) = LocatePosition(_position);
            byte[] data = GetChunk(chunkIdx);
            int available = data.Length - offsetInChunk;
            int toRead = Math.Min(count, available);
            Array.Copy(data, offsetInChunk, buffer, offset + totalRead, toRead);

            _position += toRead;
            totalRead += toRead;
            count -= toRead;
        }
        return totalRead;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_position >= _totalLength) return 0;
        int count = (int)Math.Min(buffer.Length, _totalLength - _position);
        int totalRead = 0;

        while (count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            (int chunkIdx, int offsetInChunk) = LocatePosition(_position);
            byte[] data = await GetChunkAsync(chunkIdx, cancellationToken);
            int available = data.Length - offsetInChunk;
            int toRead = Math.Min(count, available);
            data.AsMemory(offsetInChunk, toRead).CopyTo(buffer.Slice(totalRead));

            _position += toRead;
            totalRead += toRead;
            count -= toRead;
        }
        return totalRead;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        long target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _totalLength + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        ArgumentOutOfRangeException.ThrowIfNegative(target);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(target, _totalLength);
        _position = target;
        return _position;
    }

    private (int ChunkIndex, int OffsetInChunk) LocatePosition(long position)
    {
        int lo = 0, hi = _cumulativeSizes.Length - 1;
        while (lo < hi)
        {
            int mid = (lo + hi + 1) / 2;
            if (_cumulativeSizes[mid] <= position) lo = mid;
            else hi = mid - 1;
        }
        return (lo, (int)(position - _cumulativeSizes[lo]));
    }

    private byte[] GetChunk(int chunkIndex)
    {
        if (_cachedChunkIndex == chunkIndex && _cachedData is not null)
            return _cachedData;

        byte[]? data = _chunkStore.ReadChunk(_volumeName, _objectId, chunkIndex);
        if (data is null)
            throw new InvalidOperationException($"チャンク {chunkIndex} がストレージに見つかりません。");

        _cachedData = data;
        _cachedChunkIndex = chunkIndex;
        return _cachedData;
    }

    private async Task<byte[]> GetChunkAsync(int chunkIndex, CancellationToken ct = default)
    {
        if (_cachedChunkIndex == chunkIndex && _cachedData is not null)
            return _cachedData;

        byte[]? data = await _chunkStore.ReadChunkAsync(_volumeName, _objectId, chunkIndex, ct);
        if (data is null)
            throw new InvalidOperationException($"チャンク {chunkIndex} がストレージに見つかりません。");

        _cachedData = data;
        _cachedChunkIndex = chunkIndex;
        return _cachedData;
    }

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        if (disposing)
        {
            _cachedData = null;
        }
        _disposed = true;
        base.Dispose(disposing);
    }
}
