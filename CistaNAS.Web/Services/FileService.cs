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
/// async-friendly なファイル単位の読み書きゲート。
/// 複数の並行読み取りを許可し、書き込みは全読み取りの完了を待機する。
/// <see cref="ReaderWriterLockSlim"/> と異なりスレッドアフィンではないため、
/// async/await で別スレッドに継続しても正しく動作する。
/// </summary>
internal sealed class AsyncFileGate
{
    private int _readerCount;
    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <summary>読み取りロックを取得。並行読み取り可。戻り値の IDisposable で解放。</summary>
    public async Task<IDisposable> EnterReadAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        Interlocked.Increment(ref _readerCount);
        _gate.Release();
        return new ReadReleaser(this);
    }

    /// <summary>書き込みロックを取得。全読み取りの完了を待機。戻り値の IDisposable で解放。</summary>
    public async Task<IDisposable> EnterWriteAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        // アクティブな読み取りがなくなるまでスピン
        while (Volatile.Read(ref _readerCount) > 0)
        {
            _gate.Release();
            await Task.Delay(TimeSpan.FromMilliseconds(20), ct);
            await _gate.WaitAsync(ct);
        }
        // _gate を保持したまま返す → ExitWrite で解放
        return new WriteReleaser(this);
    }

    private void ExitRead() => Interlocked.Decrement(ref _readerCount);
    private void ExitWrite() => _gate.Release();

    public void Dispose() => _gate.Dispose();

    private sealed class ReadReleaser(AsyncFileGate gate) : IDisposable
    {
        public void Dispose() => gate.ExitRead();
    }

    private sealed class WriteReleaser(AsyncFileGate gate) : IDisposable
    {
        public void Dispose() => gate.ExitWrite();
    }
}

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

    /// <summary>ファイル単位の読み書きロック。ダウンロード中の上書き・削除を防止する。</summary>
    private static readonly ConcurrentDictionary<(string Volume, string File), AsyncFileGate> _fileGates = new();

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

        // ロック順序: fileGate → catLock → streamLock（デッドロック防止）
        var gate = _fileGates.GetOrAdd((volumeName, fileName), _ => new AsyncFileGate());
        using (await gate.EnterWriteAsync(ct))
        {
            return await UploadInternalAsync(volumeName, fileName, content, contentLength, ct);
        }
    }

    /// <summary>非チャンクモードのアップロード本体。</summary>
    private async Task<FileMetadata> UploadInternalAsync(string volumeName, string fileName, Stream content, long contentLength, CancellationToken ct)
    {
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
        // ロック順序: fileGate → catLock（デッドロック防止）
        var gate = _fileGates.GetOrAdd((volumeName, fileName), _ => new AsyncFileGate());
        using (await gate.EnterWriteAsync(ct))
        {
            return await UploadChunkedInternalAsync(volumeName, fileName, content, contentLength, ct);
        }
    }

    /// <summary>チャンクモードのアップロード本体。</summary>
    private async Task<FileMetadata> UploadChunkedInternalAsync(string volumeName, string fileName, Stream content, long contentLength, CancellationToken ct)
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
        // ロック順序: fileGate → catLock（デッドロック防止）
        var gate = _fileGates.GetOrAdd((volumeName, fileName), _ => new AsyncFileGate());
        var readLock = await gate.EnterReadAsync(ct);
        try
        {
            SemaphoreSlim catLock = _catalogLocks.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
            await catLock.WaitAsync(ct);
            try
            {
                var catalog = await LoadCatalogAsync(volumeName, ct);
                if (!catalog.Files.TryGetValue(fileName, out var meta))
                    throw new FileServiceException($"ファイル '{fileName}' が見つかりません。");

                if (meta.IsChunked && IsChunkMode(volumeName))
                    return DownloadChunkedResponse(volumeName, fileName, meta, readLock);

                // ローカルモード: 従来のストリームベース
                var (stream, _) = _volumeService.GetMounted(volumeName);
                long offset = meta.Offset;
                long length = meta.Length;
                string name = meta.Name;
                var streamLock = _streamLocks.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
                var inner = new FileSubStream(stream, offset, length, streamLock);
                return new FileDownloadResponse(new GateReadStream(inner, readLock), name, length);
            }
            finally
            {
                catLock.Release();
            }
        }
        catch
        {
            // ストリームが正常に返されなかった場合は読み取りゲートを解放
            readLock.Dispose();
            throw;
        }
    }

    /// <summary>チャンクモード: チャンクを遅延取得して Seekable なストリームで返す。</summary>
    private FileDownloadResponse DownloadChunkedResponse(string volumeName, string fileName, FileMetadata meta, IDisposable readLock)
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

        return new FileDownloadResponse(new GateReadStream(chunkedStream, readLock), meta.Name, meta.Length);
    }

    /// <summary>ファイルを削除。</summary>
    public async Task DeleteAsync(string volumeName, string fileName, CancellationToken ct = default)
    {
        bool isChunkMode = IsChunkMode(volumeName);

        // ロック順序: fileGate → catLock（デッドロック防止）
        var gate = _fileGates.GetOrAdd((volumeName, fileName), _ => new AsyncFileGate());
        using (await gate.EnterWriteAsync(ct))
        {
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

        // 削除完了後にファイルゲートをクリーンアップ
        if (_fileGates.TryRemove((volumeName, fileName), out var removed))
            removed.Dispose();
    }

    /// <summary>クラッシュ復旧：未コミットジャーナルからカタログを修復。</summary>
    public async Task RecoverAsync(string volumeName, CancellationToken ct = default)
    {
        var pending = await _journalService.RecoverAsync(volumeName, ct);
        if (pending.Count == 0) return;

        // 削除済みエントリはカタログから取り除く
        var catalog = await LoadCatalogAsync(volumeName, ct);
        foreach (var entry in pending)
        {
            if (entry.Operation == JournalOp.DeleteFile)
                catalog.Files.Remove(entry.Path);
        }

        // チャンクモード: WriteFile 未完了のファイルでチャンク欠落がある場合はカタログから削除
        if (IsChunkMode(volumeName))
        {
            var brokenFiles = new List<string>();
            foreach (var (fileName, meta) in catalog.Files)
            {
                if (!meta.IsChunked) continue;
                try
                {
                    var indices = await _chunkStore.ListChunksAsync(volumeName, fileName, ct);
                    if (indices.Count < meta.ChunkCount)
                        brokenFiles.Add(fileName);
                }
                catch (Exception)
                {
                    // チャンク一覧の取得自体が失敗 → ファイルを broken 扱い
                    brokenFiles.Add(fileName);
                }
            }
            foreach (var broken in brokenFiles)
                catalog.Files.Remove(broken);
        }

        await SaveCatalogAsync(volumeName, catalog, ct);
        await _journalService.CommitAsync(volumeName, ct);
    }

    /// <summary>ボリューム削除時に対応するカタログロックを破棄。</summary>
    public static void RemoveCatalogLock(string volumeName)
    {
        if (_catalogLocks.TryRemove(volumeName, out var gate))
            gate.Dispose();
        RemoveFileGatesForVolume(volumeName);
    }

    /// <summary>ボリューム削除時に対応するストリームロックを破棄。</summary>
    public static void RemoveStreamLock(string volumeName)
    {
        if (_streamLocks.TryRemove(volumeName, out var gate))
            gate.Dispose();
    }

    /// <summary>ボリュームに紐づく全ファイルの AsyncFileGate を破棄。</summary>
    private static void RemoveFileGatesForVolume(string volumeName)
    {
        foreach (var key in _fileGates.Keys)
        {
            if (key.Volume == volumeName && _fileGates.TryRemove(key, out var g))
                g.Dispose();
        }
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

/// <summary>
/// ダウンロード中の読み取りゲートを保持するストリームラッパー。
/// Dispose 時にファイルゲートの読み取りロックを解放し、アップロード/削除を許可する。
/// </summary>
file sealed class GateReadStream(Stream inner, IDisposable gateLock) : Stream
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
        streamLock.Wait();
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
            Buffer.BlockCopy(data, offsetInChunk, buffer, offset + totalRead, toRead);

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
        return data;
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
        return data;
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
