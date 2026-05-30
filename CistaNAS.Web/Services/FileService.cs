using System.Collections.Concurrent;
using System.Text.Json;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Crypto;
using CistaNAS.Web.Journal;
using CistaNAS.Web.Models;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// マウント済みボリューム内のファイル読み書き・一覧・削除。Scoped 登録。
/// VolumeService（Singleton マウント状態）と JournalService に依存。
/// </summary>
/// <remarks>
/// <para>ボリューム内のファイル管理方式：</para>
/// <para>
/// - volume.dat の暗号化ストリームの末尾にファイルデータを追記
/// - catalog.json（同じディレクトリに平文で保存、アクセス制御で保護）に
///   ファイル名→オフセット/長さのマッピングを保持
/// - ジャーナルで書き込み前後の一貫性を保証
/// </para>
/// </remarks>
public sealed class FileService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> _catalogLocks = new(StringComparer.Ordinal);
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> _streamLocks = new(StringComparer.Ordinal);

    private readonly VolumeService _volumeService;
    private readonly JournalService _journalService;
    private readonly IStorageProvider _storage;
    private readonly IChunkStore _chunkStore;

    public FileService(
        VolumeService volumeService,
        JournalService journalService,
        IStorageProvider storage,
        IChunkStore chunkStore)
    {
        _volumeService = volumeService;
        _journalService = journalService;
        _storage = storage;
        _chunkStore = chunkStore;
    }

    /// <summary>ボリュームがチャンクストレージモードか。</summary>
    private bool IsChunkMode(string volumeName)
    {
        var (header, _) = _volumeService.GetMountedKeys(volumeName);
        return header.StorageMode == "chunk";
    }

    /// <summary>ボリュームのマウント情報（チャンク暗号化用）を取得。</summary>
    private (VolumeHeader Header, byte[]? MasterKey) GetVolumeKeys(string volumeName)
        => _volumeService.GetMountedKeys(volumeName);

    /// <summary>ボリューム内の全ファイルを一覧。</summary>
    public async Task<ListFilesResponse> ListAsync(string volumeName, CancellationToken ct = default)
    {
        var catalog = await LoadCatalogAsync(volumeName, ct);
        return new ListFilesResponse(catalog.Files.Values.OrderBy(f => f.Name).ToList());
    }

    /// <summary>ファイルをアップロード（新規 or 上書き）。</summary>
    public async Task<FileMetadata> UploadAsync(string volumeName, string fileName, Stream content, long contentLength, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        if (contentLength < 0) throw new ArgumentOutOfRangeException(nameof(contentLength));

        if (IsChunkMode(volumeName))
            return await UploadChunkedAsync(volumeName, fileName, content, contentLength, ct);

        var (stream, _) = _volumeService.GetMounted(volumeName);

        // ジャーナル: 書き込み前
        await _journalService.RecordAsync(volumeName, new JournalEntry
        {
            Operation = JournalOp.WriteFile,
            Path = fileName,
            Length = checked((int)Math.Min(contentLength, int.MaxValue)),
        }, ct);

        // カタログ読み込み + ストリーム書き込み + カタログ保存をボリュームロックで保護
        long offset;
        long writtenBytes;
        FileMetadata meta;
        SemaphoreSlim catLock = _catalogLocks.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        await catLock.WaitAsync(ct);
        try
        {
            var catalog = await LoadCatalogAsync(volumeName, ct);
            catalog.Files.TryGetValue(fileName, out var existing);

            SemaphoreSlim streamLock = _streamLocks.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
            await streamLock.WaitAsync(ct);
            try
            {
                if (existing is not null && existing.Length >= contentLength)
                {
                    offset = existing.Offset;
                }
                else
                {
                    offset = stream.Length;
                }

                stream.Seek(offset, SeekOrigin.Begin);

                // チャンク単位で読み取り→書き込み（メモリにファイル全体をバッファリングしない）
                byte[] buffer = new byte[81920];
                long remaining = contentLength;
                writtenBytes = 0;
                while (remaining > 0)
                {
                    int toRead = (int)Math.Min(buffer.Length, remaining);
                    int read = await content.ReadAsync(buffer.AsMemory(0, toRead), ct);
                    if (read == 0) break;
                    await stream.WriteAsync(buffer.AsMemory(0, read), ct);
                    writtenBytes += read;
                    remaining -= read;
                }
                await stream.FlushAsync(ct);
            }
            finally
            {
                streamLock.Release();
            }

            meta = new FileMetadata
            {
                Name = fileName,
                Offset = offset,
                Length = writtenBytes,
                CreatedAt = existing?.CreatedAt ?? DateTimeOffset.UtcNow,
                ModifiedAt = DateTimeOffset.UtcNow,
            };
            catalog.Files[fileName] = meta;
            await SaveCatalogAsync(volumeName, catalog, ct);
        }
        finally
        {
            catLock.Release();
        }

        // ジャーナル: コミット
        await _journalService.CommitAsync(volumeName, ct);

        return meta;
    }

    /// <summary>チャンクモード: ファイルをチャンク分割して暗号化し S3 に保存。</summary>
    private async Task<FileMetadata> UploadChunkedAsync(string volumeName, string fileName, Stream content, long contentLength, CancellationToken ct = default)
    {
        var (header, masterKey) = GetVolumeKeys(volumeName);
        int chunkSize = header.ServerChunkSize > 0 ? header.ServerChunkSize : 4194304;

        // ジャーナル: 書き込み前
        await _journalService.RecordAsync(volumeName, new JournalEntry
        {
            Operation = JournalOp.WriteFile,
            Path = fileName,
            Length = checked((int)Math.Min(contentLength, int.MaxValue)),
        }, ct);

        SemaphoreSlim catLock = _catalogLocks.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        await catLock.WaitAsync(ct);
        try
        {
            var catalog = await LoadCatalogAsync(volumeName, ct);
            catalog.Files.TryGetValue(fileName, out var existing);

            // 既存ファイルのチャンクを削除（上書き時）
            if (existing is not null && existing.IsChunked)
            {
                try { await _chunkStore.DeleteChunksAsync(volumeName, fileName, ct); }
                catch (Exception) { /* ベストエフォート */ }
            }

            var chunkSizes = new List<int>();
            byte[] buffer = new byte[chunkSize];
            int chunkIndex = 0;
            long remaining = contentLength;
            int sectorSize = header.SectorSize > 0 ? header.SectorSize : 4096;

            while (remaining > 0)
            {
                int toRead = (int)Math.Min(buffer.Length, remaining);
                int read = await content.ReadAsync(buffer.AsMemory(0, toRead), ct);
                if (read == 0) break;

                byte[] chunkData = buffer[..read].ToArray();

                // 暗号化ボリュームの場合は AES-XTS でチャンク暗号化
                if (header.Encrypted && masterKey is not null)
                {
                    chunkData = ChunkEncryptor.EncryptChunk(masterKey, chunkIndex, sectorSize, chunkSize, chunkData);
                }

                // S3 にチャンクを保存
                using var ms = new MemoryStream(chunkData);
                await _chunkStore.WriteChunkAsync(volumeName, fileName, chunkIndex, ms, ct);

                chunkSizes.Add(read);
                chunkIndex++;
                remaining -= read;
            }

            var meta = new FileMetadata
            {
                Name = fileName,
                Offset = 0, // チャンクモードでは使用しない
                Length = contentLength - remaining, // 実際に読み取ったバイト数
                ChunkCount = chunkSizes.Count,
                ChunkSizes = chunkSizes,
                CreatedAt = existing?.CreatedAt ?? DateTimeOffset.UtcNow,
                ModifiedAt = DateTimeOffset.UtcNow,
            };
            catalog.Files[fileName] = meta;
            await SaveCatalogAsync(volumeName, catalog, ct);

            await _journalService.CommitAsync(volumeName, ct);
            return meta;
        }
        finally
        {
            catLock.Release();
        }
    }

    /// <summary>ファイルをダウンロード。</summary>
    public async Task<FileDownloadResponse> DownloadAsync(string volumeName, string fileName, CancellationToken ct = default)
    {
        SemaphoreSlim catLock = _catalogLocks.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        await catLock.WaitAsync(ct);
        try
        {
            var catalog = await LoadCatalogAsync(volumeName, ct);
            if (!catalog.Files.TryGetValue(fileName, out var meta))
                throw new FileServiceException($"ファイル '{fileName}' が見つかりません。");

            if (meta.IsChunked && IsChunkMode(volumeName))
                return await DownloadChunkedAsync(volumeName, fileName, meta, ct);

            // ローカルモード: 従来のストリームベース
            var (stream, _) = _volumeService.GetMounted(volumeName);
            long offset = meta.Offset;
            long length = meta.Length;
            string name = meta.Name;
            var streamLock = _streamLocks.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
            return new FileDownloadResponse(new FileSubStream(stream, offset, length, streamLock), name, length);
        }
        finally
        {
            catLock.Release();
        }
    }

    /// <summary>チャンクモード: チャンクを遅延取得して Seekable なストリームで返す。</summary>
    private Task<FileDownloadResponse> DownloadChunkedAsync(string volumeName, string fileName, FileMetadata meta, CancellationToken ct)
    {
        var (header, masterKey) = GetVolumeKeys(volumeName);
        int sectorSize = header.SectorSize > 0 ? header.SectorSize : 4096;
        int chunkSize = header.ServerChunkSize > 0 ? header.ServerChunkSize : 4194304;

        Stream chunkedStream;
        if (header.Encrypted && masterKey is not null)
        {
            chunkedStream = new ChunkedReadStream(
                _chunkStore, volumeName, fileName, masterKey,
                sectorSize, chunkSize, meta.ChunkSizes);
        }
        else
        {
            // 非暗号化: ChunkedReadStream の代わりに MemoryChunkedStream を使用
            chunkedStream = new MemoryChunkedStream(_chunkStore, volumeName, fileName, meta.ChunkSizes);
        }

        return Task.FromResult(new FileDownloadResponse(chunkedStream, meta.Name, meta.Length));
    }

    /// <summary>ファイルを削除。</summary>
    public async Task DeleteAsync(string volumeName, string fileName, CancellationToken ct = default)
    {
        bool isChunkMode = IsChunkMode(volumeName);

        await _journalService.RecordAsync(volumeName, new JournalEntry
        {
            Operation = JournalOp.DeleteFile,
            Path = fileName,
        }, ct);

        SemaphoreSlim catLock = _catalogLocks.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        await catLock.WaitAsync(ct);
        try
        {
            var catalog = await LoadCatalogAsync(volumeName, ct);
            if (!catalog.Files.Remove(fileName))
                throw new FileServiceException($"ファイル '{fileName}' が見つかりません。");

            await SaveCatalogAsync(volumeName, catalog, ct);
        }
        finally
        {
            catLock.Release();
        }

        // チャンクモード: S3 からチャンクを削除
        if (isChunkMode)
        {
            try { await _chunkStore.DeleteChunksAsync(volumeName, fileName, ct); }
            catch (Exception) { /* ベストエフォート */ }
        }

        await _journalService.CommitAsync(volumeName, ct);
    }

    /// <summary>クラッシュ復旧：未コミットジャーナルからカタログを修復。</summary>
    public async Task RecoverAsync(string volumeName, CancellationToken ct = default)
    {
        var pending = await _journalService.RecoverAsync(volumeName, ct);
        if (pending.Count == 0) return;

        // 書き込み未完了エントリは無視（次回上書きで回復）
        // 削除済みエントリはカタログから取り除く
        var catalog = await LoadCatalogAsync(volumeName, ct);
        foreach (var entry in pending)
        {
            if (entry.Operation == JournalOp.DeleteFile)
                catalog.Files.Remove(entry.Path);
        }
        await SaveCatalogAsync(volumeName, catalog, ct);
        await _journalService.CommitAsync(volumeName, ct);
    }

    /// <summary>ボリューム削除時に対応するカタログロックを破棄。</summary>
    public static void RemoveCatalogLock(string volumeName)
    {
        if (_catalogLocks.TryRemove(volumeName, out var gate))
            gate.Dispose();
    }

    /// <summary>ボリューム削除時に対応するストリームロックを破棄。</summary>
    public static void RemoveStreamLock(string volumeName)
    {
        if (_streamLocks.TryRemove(volumeName, out var gate))
            gate.Dispose();
    }

    // ---- カタログ ----

    private sealed class FileCatalog
    {
        public Dictionary<string, FileMetadata> Files { get; set; } = new(StringComparer.Ordinal);
    }

    private async Task<FileCatalog> LoadCatalogAsync(string volumeName, CancellationToken ct)
    {
        byte[]? data = await _storage.ReadAsync($"{volumeName}/catalog.json", ct);
        if (data is null) return new FileCatalog();
        return JsonSerializer.Deserialize<FileCatalog>(data, JsonOptions) ?? new FileCatalog();
    }

    private async Task SaveCatalogAsync(string volumeName, FileCatalog catalog, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        JsonSerializer.Serialize(ms, catalog, JsonOptions);
        ms.Position = 0;
        await _storage.WriteAtomicAsync($"{volumeName}/catalog.json", ms, ct);
    }
}

/// <summary>ボリュームストリームの部分範囲を読み取るラッパー。基礎ストリームは破棄しない。</summary>
file sealed class FileSubStream(Stream baseStream, long offset, long length, SemaphoreSlim streamLock) : Stream
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
        streamLock.WaitAsync().GetAwaiter().GetResult();
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

/// <summary>非暗号化チャンクストアから遅延取得する Seekable ストリーム。</summary>
file sealed class MemoryChunkedStream : Stream
{
    private readonly IChunkStore _chunkStore;
    private readonly string _volumeName;
    private readonly string _objectId;
    private readonly IReadOnlyList<int> _chunkSizes;
    private readonly long[] _cumulativeSizes;
    private readonly long _totalLength;

    private long _position;
    private int _cachedChunkIndex = -1;
    private byte[]? _cachedData;

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
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, _totalLength);
            _position = value;
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_position >= _totalLength) return 0;
        count = (int)Math.Min(count, _totalLength - _position);
        int totalRead = 0;

        while (count > 0)
        {
            (int chunkIdx, int offsetInChunk) = LocatePosition(_position);
            byte[] data = GetChunk(chunkIdx);
            int available = data.Length - offsetInChunk;
            int toRead = Math.Min(count, available);
            Buffer.BlockCopy(data, offsetInChunk, buffer, offset + totalRead, toRead);

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

        byte[]? data = _chunkStore.ReadChunkAsync(_volumeName, _objectId, chunkIndex).GetAwaiter().GetResult();
        if (data is null)
            throw new InvalidOperationException($"チャンク {chunkIndex} がストレージに見つかりません。");

        _cachedData = data;
        _cachedChunkIndex = chunkIndex;
        return data;
    }

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
