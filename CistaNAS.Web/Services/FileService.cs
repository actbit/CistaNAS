using System.Collections.Concurrent;
using System.Text.Json;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Journal;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services.Streams;
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
    // 注: 以下の static フィールドは意図的にプロセス全体で共有。
    // FileService は Scoped 登録だが、Singleton な VolumeService と相互作用し、
    // Scoped の寿命が終わっても別リクエストから参照される可能性があるため、
    // 状態 (catalog lock / stream lock / file gate) は static に保持する。
    // メモリリーク防止のため、DeleteVolumeAsync / CleanupVolumeGates で明示的に解放する。
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

    /// <summary>ボリューム内の全ファイルを一覧。</summary>
    public async Task<ListFilesResponse> ListAsync(string volumeName, CancellationToken ct = default)
    {
        SemaphoreSlim catLock = _catalogLocks.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        await catLock.WaitAsync(ct);
        try
        {
            var catalog = await LoadCatalogAsync(volumeName, ct);
            return new ListFilesResponse(catalog.Files.Values.OrderBy(f => f.Name).ToList());
        }
        finally
        {
            catLock.Release();
        }
    }

    /// <summary>ファイルをアップロード（新規 or 上書き）。</summary>
    public async Task<FileMetadata> UploadAsync(string volumeName, string fileName, Stream content, long contentLength, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        if (contentLength < 0) throw new ArgumentOutOfRangeException(nameof(contentLength));

        if (_volumeService.IsChunkMode(volumeName))
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
        var (ioGuard, stream, _) = await _volumeService.GetMountedForIoAsync(volumeName, ct);
        try
        {

        // ジャーナル: 書き込み前
        string opId = await _journalService.RecordAsync(volumeName, new JournalEntry
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
        await _journalService.CommitAsync(volumeName, opId, ct);

        return meta;
        }
        finally
        {
            ioGuard.Dispose();
        }
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
        var (header, masterKey) = _volumeService.GetMountedKeys(volumeName);
        int chunkSize = header.EffectiveServerChunkSize;

        // ジャーナル: 書き込み前
        string opId = await _journalService.RecordAsync(volumeName, new JournalEntry
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
            int sectorSize = header.EffectiveSectorSize;

            while (remaining > 0)
            {
                int toRead = (int)Math.Min(buffer.Length, remaining);
                int read = await content.ReadAsync(buffer.AsMemory(0, toRead), ct);
                if (read == 0) break;

                byte[] chunkData = buffer[..read].ToArray();

                // 暗号化ボリュームの場合はチャンク暗号化
                if (header.Encrypted && masterKey is not null)
                {
                    chunkData = ChunkEncryptor.EncryptChunk(
                        masterKey, header.EffectiveCipherAlgorithm,
                        chunkIndex, sectorSize, chunkSize, chunkData);
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

            await _journalService.CommitAsync(volumeName, opId, ct);
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

                if (meta.IsChunked && _volumeService.IsChunkMode(volumeName))
                    return DownloadChunkedResponse(volumeName, fileName, meta, readLock);

                // ローカルモード: 従来のストリームベース
                var (ioGuard, stream, _) = await _volumeService.GetMountedForIoAsync(volumeName, ct);
                long offset = meta.Offset;
                long length = meta.Length;
                string name = meta.Name;
                var streamLock = _streamLocks.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
                var inner = new FileSubStream(stream, offset, length, streamLock);
                return new FileDownloadResponse(new IoGuardReadStream(new GateReadStream(inner, readLock), ioGuard), name, length);
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
        var (header, masterKey) = _volumeService.GetMountedKeys(volumeName);
        int sectorSize = header.EffectiveSectorSize;
        int chunkSize = header.EffectiveServerChunkSize;

        Stream chunkedStream;
        if (header.Encrypted && masterKey is not null)
        {
            chunkedStream = new ChunkedReadStream(
                _chunkStore, volumeName, fileName, masterKey,
                header.EffectiveCipherAlgorithm,
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
        bool isChunkMode = _volumeService.IsChunkMode(volumeName);

        // ロック順序: fileGate → catLock（デッドロック防止）
        var gate = _fileGates.GetOrAdd((volumeName, fileName), _ => new AsyncFileGate());
        using (await gate.EnterWriteAsync(ct))
        {
            string opId = await _journalService.RecordAsync(volumeName, new JournalEntry
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

            // チャンクモード: S3 からチャンクを削除（リトライ付き）
            if (isChunkMode)
            {
                await _chunkStore.DeleteChunksWithRetryAsync(volumeName, fileName, ct);
            }

            await _journalService.CommitAsync(volumeName, opId, ct);
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
        if (_volumeService.IsChunkMode(volumeName))
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
        await _journalService.CommitAllAsync(volumeName, ct);
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
