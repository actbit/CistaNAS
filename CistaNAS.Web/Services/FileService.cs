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

                // 既存ファイル領域を再利用して短くなった場合、残領域を暗号化ゼロでクリア。
                // カタログは writtenBytes で短縮記録されるが、volume.dat 上の残りバイトに
                // 旧内容（暗号文）が残留するのを防ぐ。
                if (existing is not null && existing.Length >= contentLength && existing.Length > writtenBytes)
                {
                    stream.Seek(offset + writtenBytes, SeekOrigin.Begin);
                    Array.Clear(buffer, 0, buffer.Length);
                    long zRemain = existing.Length - writtenBytes;
                    while (zRemain > 0)
                    {
                        int n = (int)Math.Min(buffer.Length, zRemain);
                        await stream.WriteAsync(buffer.AsMemory(0, n), ct);
                        zRemain -= n;
                    }
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

    /// <summary>ファイルの一部を書き込む（差分保存）。既存ファイルの offset に上書き、必要に応じて拡張。</summary>
    public async Task<FileMetadata> PatchRangeAsync(string volumeName, string fileName, long offset, Stream content, long contentLength, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
        if (contentLength < 0) throw new ArgumentOutOfRangeException(nameof(contentLength));

        if (_volumeService.IsChunkMode(volumeName))
            return await PatchChunkedAsync(volumeName, fileName, offset, content, contentLength, ct);

        // ロック順序: fileGate → catLock → streamLock（デッドロック防止）
        var gate = _fileGates.GetOrAdd((volumeName, fileName), _ => new AsyncFileGate());
        using (await gate.EnterWriteAsync(ct))
        {
            return await PatchInternalAsync(volumeName, fileName, offset, content, contentLength, ct);
        }
    }

    /// <summary>非チャンクモードの部分書き込み本体。AesXtsStream のセクタ単位 RMW で安全に部分上書き。</summary>
    private async Task<FileMetadata> PatchInternalAsync(string volumeName, string fileName, long offset, Stream content, long contentLength, CancellationToken ct)
    {
        var (ioGuard, stream, _) = await _volumeService.GetMountedForIoAsync(volumeName, ct);
        try
        {
        string opId = await _journalService.RecordAsync(volumeName, new JournalEntry
        {
            Operation = JournalOp.WriteFile,
            Path = fileName,
            Length = checked((int)Math.Min(contentLength, int.MaxValue)),
        }, ct);

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
                long baseOffset = existing?.Offset ?? stream.Length;
                byte[] buffer = new byte[81920];

                // 新規ファイルで offset > 0（sparse）: baseOffset..baseOffset+offset を暗号化ゼロで埋める。
                // AesXtsStream は平文ゼロを暗号化ゼロとして書き込む。
                if (existing is null && offset > 0)
                {
                    stream.Seek(baseOffset, SeekOrigin.Begin);
                    Array.Clear(buffer, 0, buffer.Length);
                    long zRemain = offset;
                    while (zRemain > 0)
                    {
                        int n = (int)Math.Min(buffer.Length, zRemain);
                        await stream.WriteAsync(buffer.AsMemory(0, n), ct);
                        zRemain -= n;
                    }
                }

                stream.Seek(baseOffset + offset, SeekOrigin.Begin);
                long remaining = contentLength;
                long written = 0;
                while (remaining > 0)
                {
                    int toRead = (int)Math.Min(buffer.Length, remaining);
                    int read = await content.ReadAsync(buffer.AsMemory(0, toRead), ct);
                    if (read == 0) break;
                    await stream.WriteAsync(buffer.AsMemory(0, read), ct);
                    written += read;
                    remaining -= read;
                }
                await stream.FlushAsync(ct);

                long logicalEnd = baseOffset + offset + written;
                long newLength = existing is not null
                    ? Math.Max(existing.Length, logicalEnd - baseOffset)
                    : (logicalEnd - baseOffset);

                meta = new FileMetadata
                {
                    Name = fileName,
                    Offset = baseOffset,
                    Length = newLength,
                    CreatedAt = existing?.CreatedAt ?? DateTimeOffset.UtcNow,
                    ModifiedAt = DateTimeOffset.UtcNow,
                };
                catalog.Files[fileName] = meta;
                await SaveCatalogAsync(volumeName, catalog, ct);
            }
            finally
            {
                streamLock.Release();
            }
        }
        finally
        {
            catLock.Release();
        }

        await _journalService.CommitAsync(volumeName, opId, ct);
        return meta;
        }
        finally
        {
            ioGuard.Dispose();
        }
    }

    /// <summary>チャンクモードの部分書き込み本体。該当チャンクを RMW（復号→部分更新→再暗号化）して S3 に上書き。</summary>
    private async Task<FileMetadata> PatchChunkedAsync(string volumeName, string fileName, long offset, Stream content, long contentLength, CancellationToken ct)
    {
        var (header, masterKey) = _volumeService.GetMountedKeys(volumeName);
        int chunkSize = header.EffectiveServerChunkSize;
        int sectorSize = header.EffectiveSectorSize;
        var algorithm = header.EffectiveCipherAlgorithm;
        bool encrypted = header.Encrypted && masterKey is not null;

        var gate = _fileGates.GetOrAdd((volumeName, fileName), _ => new AsyncFileGate());
        using (await gate.EnterWriteAsync(ct))
        {
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

                var chunkSizes = existing?.ChunkSizes ?? new List<int>();
                long existingLength = existing?.Length ?? 0;
                long newLength = Math.Max(existingLength, offset + contentLength);
                int firstChunk = (int)(offset / chunkSize);
                int lastChunk = (int)((offset + contentLength - 1) / chunkSize);
                int lastNeeded = (int)((newLength - 1) / chunkSize);

                // 書き込みデータを一時バッファへ（差分編集なので通常小さい）
                byte[] contentData = new byte[contentLength];
                int totalRead = 0;
                while (totalRead < contentLength)
                {
                    int n = await content.ReadAsync(contentData.AsMemory(totalRead, (int)contentLength - totalRead), ct);
                    if (n == 0) break;
                    totalRead += n;
                }

                for (int ci = 0; ci <= lastNeeded; ci++)
                {
                    bool inWriteRange = ci >= firstChunk && ci <= lastChunk;
                    bool isExisting = ci < chunkSizes.Count;
                    // 既存チャンクで書き込み範囲外 → 维持（再書き込みしない）
                    if (!inWriteRange && isExisting) continue;

                    int curPlainSize = (int)Math.Min(chunkSize, newLength - (long)ci * chunkSize);
                    if (curPlainSize <= 0) break;

                    byte[] plain = new byte[curPlainSize];
                    if (encrypted && isExisting && chunkSizes[ci] > 0)
                    {
                        byte[]? enc = await _chunkStore.ReadChunkAsync(volumeName, fileName, ci, ct);
                        if (enc is not null)
                        {
                            int origLen = Math.Min(chunkSizes[ci], curPlainSize);
                            var dec = ChunkEncryptor.DecryptChunk(masterKey!, algorithm, ci, sectorSize, chunkSize, enc, origLen);
                            Array.Copy(dec, plain, Math.Min(dec.Length, plain.Length));
                        }
                    }

                    if (inWriteRange)
                    {
                        long chunkStart = (long)ci * chunkSize;
                        long relStart = Math.Max(0, offset - chunkStart);
                        long relEnd = Math.Min(curPlainSize, offset + totalRead - chunkStart);
                        long srcStart = Math.Max(0, chunkStart - offset);
                        int copyLen = (int)(relEnd - relStart);
                        if (copyLen > 0)
                            Array.Copy(contentData, (int)srcStart, plain, (int)relStart, copyLen);
                    }

                    byte[] stored = encrypted
                        ? ChunkEncryptor.EncryptChunk(masterKey!, algorithm, ci, sectorSize, chunkSize, plain)
                        : plain;
                    using var ms = new MemoryStream(stored);
                    await _chunkStore.WriteChunkAsync(volumeName, fileName, ci, ms, ct);

                    while (chunkSizes.Count <= ci) chunkSizes.Add(0);
                    chunkSizes[ci] = curPlainSize;
                }

                var meta = new FileMetadata
                {
                    Name = fileName,
                    Offset = 0,
                    Length = newLength,
                    ChunkCount = lastNeeded + 1,
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

    /// <summary>クラッシュ復旧：未コミットジャーナルからカタログを修復し、ジャーナルをクリアする。</summary>
    /// <remarks>
    /// マウント直後（MountAsync / MountE2eeAsync）に呼ばれる。カタログ操作は通常の読み書きと
    /// 同じボリューム単位のカタログロックで直列化し、進行中の Upload/Delete との競合を防ぐ。
    /// </remarks>
    public async Task RecoverAsync(string volumeName, CancellationToken ct = default)
    {
        var pending = await _journalService.RecoverAsync(volumeName, ct);
        if (pending.Count == 0) return;

        SemaphoreSlim catLock = _catalogLocks.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        await catLock.WaitAsync(ct);
        try
        {
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
        finally
        {
            catLock.Release();
        }
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
