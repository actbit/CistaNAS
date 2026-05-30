using System.Security.Cryptography;
using CistaNAS.Web.Crypto;
using CistaNAS.Web.Storage;

namespace CistaNAS.Web.Services;

/// <summary>
/// チャンクストアから遅延取得しながら復号する Seekable ストリーム。
/// 1チャンク分だけメモリに保持し、Range 対応（enableRangeProcessing）。
/// サーバー側暗号化（AES-XTS）のチャンクモードで使用。
/// </summary>
public sealed class ChunkedReadStream : Stream
{
    private readonly IChunkStore _chunkStore;
    private readonly string _volumeName;
    private readonly string _objectId;
    private readonly byte[] _masterKey;
    private readonly int _sectorSize;
    private readonly int _chunkSize;
    private readonly IReadOnlyList<int> _chunkSizes;
    private readonly long[] _cumulativeSizes; // 前方累積サイズ（O(1) チャンク検索用）
    private readonly long _totalLength;

    private long _position;
    private int _cachedChunkIndex = -1;
    private byte[]? _cachedDecrypted; // 復号済み平文キャッシュ

    public ChunkedReadStream(
        IChunkStore chunkStore,
        string volumeName,
        string objectId,
        ReadOnlySpan<byte> masterKey,
        int sectorSize,
        int chunkSize,
        IReadOnlyList<int> chunkSizes)
    {
        _chunkStore = chunkStore;
        _volumeName = volumeName;
        _objectId = objectId;
        _masterKey = masterKey.ToArray();
        _sectorSize = sectorSize;
        _chunkSize = chunkSize;
        _chunkSizes = chunkSizes;

        // 前方累積サイズ配列を構築: cumulativeSizes[i] = チャンク 0..i-1 の合計サイズ
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
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, _totalLength);
            _position = value;
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        if (_position >= _totalLength) return 0;

        count = (int)Math.Min(count, _totalLength - _position);
        int totalRead = 0;

        while (count > 0)
        {
            (int chunkIdx, int offsetInChunk) = LocatePosition(_position);
            byte[] plain = GetDecryptedChunk(chunkIdx);
            int available = plain.Length - offsetInChunk;
            int toRead = Math.Min(count, available);
            Buffer.BlockCopy(plain, offsetInChunk, buffer, offset + totalRead, toRead);

            _position += toRead;
            totalRead += toRead;
            count -= toRead;
        }

        return totalRead;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
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

    /// <summary>
    /// グローバル位置からチャンクインデックスとチャンク内オフセットを O(log n) で取得。
    /// </summary>
    private (int ChunkIndex, int OffsetInChunk) LocatePosition(long position)
    {
        // 二分探索でチャンクインデックスを特定
        int lo = 0, hi = _cumulativeSizes.Length - 1;
        while (lo < hi)
        {
            int mid = (lo + hi + 1) / 2;
            if (_cumulativeSizes[mid] <= position)
                lo = mid;
            else
                hi = mid - 1;
        }
        return (lo, (int)(position - _cumulativeSizes[lo]));
    }

    /// <summary>
    /// チャンクを復号してキャッシュ。既にキャッシュ済みなら再利用。
    /// Stream.Read は同期メソッドのため、同期コンテキストで実行。
    /// </summary>
    private byte[] GetDecryptedChunk(int chunkIndex)
    {
        if (_cachedChunkIndex == chunkIndex && _cachedDecrypted is not null)
            return _cachedDecrypted;

        byte[]? encrypted = _chunkStore.ReadChunkAsync(
            _volumeName, _objectId, chunkIndex).GetAwaiter().GetResult();
        if (encrypted is null)
            throw new InvalidOperationException($"チャンク {chunkIndex} がストレージに見つかりません。");

        int originalLength = chunkIndex < _chunkSizes.Count ? _chunkSizes[chunkIndex] : encrypted.Length;
        byte[] plain = ChunkEncryptor.DecryptChunk(
            _masterKey, chunkIndex, _sectorSize, _chunkSize, encrypted, originalLength);

        _cachedDecrypted = plain;
        _cachedChunkIndex = chunkIndex;
        return plain;
    }

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _cachedDecrypted = null;
            CryptographicOperations.ZeroMemory(_masterKey);
        }
        base.Dispose(disposing);
    }
}
