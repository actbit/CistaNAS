using System.Collections.Concurrent;
using System.Security.Cryptography;
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
        ValidateSizeBound(contentLength);

        if (_volumeService.IsChunkMode(volumeName))
            return await UploadChunkedAsync(volumeName, fileName, content, contentLength, ct);

        // ロック順序: fileGate → catLock → streamLock（デッドロック防止）
        var gate = _fileGates.GetOrAdd((volumeName, fileName), _ => new AsyncFileGate());
        using (await gate.EnterWriteAsync(ct))
        {
            return await UploadInternalAsync(volumeName, fileName, content, contentLength, ct);
        }
    }

    /// <summary>
    /// サイズ上限（Volume:MaxFileSizeBytes）の検査。
    /// 回帰 (High): PATCH の巨大 offset（上限なし）で新規ファイルへの sparse 埋めが
    /// 大量 I/O・ディスク枯渇を引き起こせていた。
    /// </summary>
    /// <remarks>
    /// オーバーフロー排除は呼び出し側の責務（<paramref name="endPosition"/> は
    /// checked 済みの末端位置）。単一の long への checked は決してスローしないため、
    /// ここでの try/catch はデッドコードになる（round 5 では捕捉できるように見える
    /// コメントが付いていた）。
    /// </remarks>
    private void ValidateSizeBound(long endPosition)
    {
        long max = _volumeService.MaxFileSizeBytes;
        if (endPosition > max)
            throw new FileServiceException(
                $"ファイルサイズが上限 ({max:N0} バイト) を超えています。末端位置: {endPosition:N0} バイト。");
    }

    /// <summary>非チャンクモードのアップロード本体。</summary>
    private Task<FileMetadata> UploadInternalAsync(string volumeName, string fileName, Stream content, long contentLength, CancellationToken ct)
        => WriteLocalAsync(volumeName, fileName, 0, content, contentLength, patch: false, ct);

    /// <summary>ファイルの一部を書き込む（差分保存）。未変更の内容を保持し、必要に応じて拡張。</summary>
    public async Task<FileMetadata> PatchRangeAsync(string volumeName, string fileName, long offset, Stream content, long contentLength, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
        if (contentLength < 0) throw new ArgumentOutOfRangeException(nameof(contentLength));
        // offset + contentLength が末端位置。オーバーフローは上限拒否（400）へ変換する
        // （round 6: 生の OverflowException がハンドラをすり抜けて 500 になっていた）。
        long endPosition;
        try { endPosition = checked(offset + contentLength); }
        catch (OverflowException) { throw new FileServiceException("要求サイズが大きすぎます。"); }
        ValidateSizeBound(endPosition);

        if (_volumeService.IsChunkMode(volumeName))
            return await PatchChunkedAsync(volumeName, fileName, offset, content, contentLength, ct);

        // ロック順序: fileGate → catLock → streamLock（デッドロック防止）
        var gate = _fileGates.GetOrAdd((volumeName, fileName), _ => new AsyncFileGate());
        using (await gate.EnterWriteAsync(ct))
        {
            return await PatchInternalAsync(volumeName, fileName, offset, content, contentLength, ct);
        }
    }

    /// <summary>非チャンクモードの部分書き込み本体。</summary>
    private Task<FileMetadata> PatchInternalAsync(string volumeName, string fileName, long offset, Stream content, long contentLength, CancellationToken ct)
        => WriteLocalAsync(volumeName, fileName, offset, content, contentLength, patch: true, ct);

    /// <summary>
    /// 新しい領域に完全な内容を構築し、フラッシュ後にカタログを切り替える。
    /// 本文不足・キャンセル・保存失敗時にも既存領域は変更しない。
    /// PATCH の拡張が隣接ファイルを上書きしたり、その内容を隙間として公開することも防ぐ。
    /// </summary>
    private async Task<FileMetadata> WriteLocalAsync(string volumeName, string fileName, long offset,
        Stream content, long contentLength, bool patch, CancellationToken ct)
    {
        var (ioGuard, stream, _) = await _volumeService.GetMountedForIoAsync(volumeName, ct);
        using (ioGuard)
        {
            string opId = await _journalService.RecordAsync(volumeName, new JournalEntry
            {
                Operation = JournalOp.WriteFile,
                Path = fileName,
                Length = (int)Math.Min(contentLength, int.MaxValue),
            }, ct);

            var catLock = _catalogLocks.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
            await catLock.WaitAsync(ct);
            try
            {
                using var distributedCatalogLock = await AcquireCatalogLockAsync(volumeName, ct);
                var catalog = await LoadCatalogAsync(volumeName, ct);
                catalog.Files.TryGetValue(fileName, out var existing);
                if (patch && contentLength == 0 && existing is not null)
                {
                    await _journalService.CommitAsync(volumeName, opId, ct);
                    return existing;
                }

                var streamLock = _streamLocks.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
                await streamLock.WaitAsync(ct);
                byte[] buffer = new byte[81920];
                long newOffset = stream.Length;
                bool publicationStarted = false;
                try
                {
                    long oldLength = patch ? existing?.Length ?? 0 : 0;
                    long newLength = contentLength == 0 ? 0 : Math.Max(oldLength, checked(offset + contentLength));

                    // 同一ストリームなので読み取りと書き込みの位置を各回明示する。
                    for (long copied = 0; copied < oldLength;)
                    {
                        int count = (int)Math.Min(buffer.Length, oldLength - copied);
                        stream.Position = existing!.Offset + copied;
                        await stream.ReadExactlyAsync(buffer.AsMemory(0, count), ct);
                        stream.Position = newOffset + copied;
                        await stream.WriteAsync(buffer.AsMemory(0, count), ct);
                        copied += count;
                    }
                    if (contentLength > 0)
                    {
                        // sparse 拡張の穴には必ず平文ゼロを書き、旧データを露出させない。
                        if (offset > oldLength)
                            await ClearLocalRangeAsync(stream, newOffset + oldLength, offset - oldLength, buffer, ct);
                        stream.Position = newOffset + offset;
                        long remaining = contentLength;
                        while (remaining > 0)
                        {
                            int count = (int)Math.Min(buffer.Length, remaining);
                            int read = await content.ReadAsync(buffer.AsMemory(0, count), ct);
                            if (read == 0)
                                throw new FileServiceException("リクエスト本文がContent-Lengthより短いです。");
                            await stream.WriteAsync(buffer.AsMemory(0, read), ct);
                            remaining -= read;
                        }
                    }
                    await stream.FlushAsync(ct);
                    // カタログが永続化される前に、新しいデータもディスクへ確定させる。
                    if (stream is FileStream file)
                        file.Flush(flushToDisk: true);
                    else if (stream is AesXtsStream xts)
                        xts.Flush(flushToDisk: true);

                    var meta = new FileMetadata
                    {
                        Name = fileName,
                        Offset = newOffset,
                        Length = newLength,
                        CreatedAt = existing?.CreatedAt ?? DateTimeOffset.UtcNow,
                        ModifiedAt = DateTimeOffset.UtcNow,
                    };
                    catalog.Files[fileName] = meta;
                    publicationStarted = true;
                    await SaveCatalogAsync(volumeName, catalog, ct);

                    // 新世代の公開後にだけ旧領域を消去する。切り替え前の消去はデータ欠損になる。
                    if (existing is not null && existing.Length > 0)
                    {
                        try
                        {
                            await ClearLocalRangeAsync(stream, existing.Offset, existing.Length, buffer, CancellationToken.None);
                            await stream.FlushAsync(CancellationToken.None);
                        }
                        catch (IOException) { /* 新世代は保存済み。旧領域の消去はベストエフォート。 */ }
                    }
                    await _journalService.CommitAsync(volumeName, opId, ct);
                    return meta;
                }
                catch
                {
                    // 本文受信中の失敗で伸びた領域を回収する。
                    // カタログ保存を開始した後は公開の成否が不明なため切り詰めない。
                    if (!publicationStarted)
                    {
                        try { stream.SetLength(newOffset); stream.Flush(); }
                        catch (IOException) { /* 元の失敗を保持する。旧領域は変更していない。 */ }
                    }
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(buffer);
                    streamLock.Release();
                }
            }
            finally
            {
                catLock.Release();
            }
        }
    }

    private static async Task ClearLocalRangeAsync(Stream stream, long offset, long length, byte[] buffer, CancellationToken ct)
    {
        Array.Clear(buffer);
        stream.Position = offset;
        while (length > 0)
        {
            int count = (int)Math.Min(buffer.Length, length);
            await stream.WriteAsync(buffer.AsMemory(0, count), ct);
            length -= count;
        }
    }

    /// <summary>チャンクモードの部分書き込み本体。該当チャンクを RMW（復号→部分更新→再暗号化）して S3 に上書き。</summary>
    private async Task<FileMetadata> PatchChunkedAsync(string volumeName, string fileName, long offset, Stream content, long contentLength, CancellationToken ct)
    {
        if (contentLength > int.MaxValue)
            throw new FileServiceException("差分書き込みは2GiB以下である必要があります。");

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
            string? newObjectId = null;
            bool catalogPublished = false;
            try
            {
                using var distributedCatalogLock = await AcquireCatalogLockAsync(volumeName, ct);
                var catalog = await LoadCatalogAsync(volumeName, ct);
                catalog.Files.TryGetValue(fileName, out var existing);

                if (contentLength == 0)
                {
                    if (existing is not null)
                    {
                        await _journalService.CommitAsync(volumeName, opId, ct);
                        return existing;
                    }

                    newObjectId = $"{fileName}.patch-{Guid.NewGuid():N}";
                    var empty = new FileMetadata
                    {
                        Name = fileName,
                        Offset = 0,
                        Length = 0,
                        ChunkCount = 0,
                        ChunkSizes = [],
                        ChunkObjectId = newObjectId,
                        // 空ファイルでもここでソルトを確定させる。後続の PATCH がこのソルトで
                        // 暗号化し、全チャンクが一貫した鍵スコープに収まる。
                        KeySalt = encrypted ? Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)) : null,
                        CreatedAt = DateTimeOffset.UtcNow,
                        ModifiedAt = DateTimeOffset.UtcNow,
                    };
                    catalog.Files[fileName] = empty;
                    await SaveCatalogAsync(volumeName, catalog, ct);
                    catalogPublished = true;
                    await _journalService.CommitAsync(volumeName, opId, ct);
                    return empty;
                }

                string oldObjectId = existing?.ChunkObjectId ?? fileName;
                newObjectId = $"{fileName}.patch-{Guid.NewGuid():N}";

                var chunkSizes = existing is null ? new List<int>() : new List<int>(existing.ChunkSizes);
                // 既存ファイルのソルトをそのまま使う（範囲外チャンクは暗号文のまま
                // コピーされるため、鍵スコープを跨いで混在させてはいけない）。
                // null は旧形式（レガシー: マスターキー直接使用）として透過的に扱う。
                // 新規ファイルはここで新しいソルトを生成する。生成しないと生マスターキーでの
                // 暗号化（レガシー形式）に永久固定され、別ファイル同一位置チャンクとの
                // XTS tweak 衝突（C⊕C = P⊕P 漏洩）が残る。Dokan クライアントの新規ファイル
                // 書き込みはこの PATCH 経路が主経路のため。
                byte[]? patchFileSalt = existing is not null
                    ? DecodeKeySalt(existing.KeySalt)
                    : encrypted ? RandomNumberGenerator.GetBytes(16) : null;
                long existingLength = existing?.Length ?? 0;
                long writeEnd = checked(offset + contentLength);
                long newLength = Math.Max(existingLength, writeEnd);
                int firstChunk = checked((int)(offset / chunkSize));
                int lastChunk = checked((int)((writeEnd - 1) / chunkSize));
                int lastNeeded = checked((int)((newLength - 1) / chunkSize));

                // 書き込みデータを一時バッファへ（差分編集なので通常小さい）
                byte[] contentData = new byte[checked((int)contentLength)];
                int totalRead = 0;
                while (totalRead < contentLength)
                {
                    int n = await content.ReadAsync(contentData.AsMemory(totalRead, (int)contentLength - totalRead), ct);
                    if (n == 0) break;
                    totalRead += n;
                }
                if (totalRead != contentLength)
                    throw new FileServiceException("リクエスト本文がContent-Lengthより短いです。");

                // ファイルスコープ鍵はループの前に一度だけ導出する（チャンクごとの HKDF 再導出を避ける）。
                // 導出は totalRead 検証などの throw 経路より後（try の直前）に行う。
                // try の前に導出すると、その間の例外で finally のゼロクリアが走らず生鍵がメモリに残留する。
                byte[]? patchScopedKey = patchFileSalt is null
                    ? null
                    : ChunkEncryptor.DeriveFileScopedKey(masterKey!, patchFileSalt, algorithm);

                try
                {
                    // 例外パスでも scoped key をゼロクリアする（ループ脱出の全経路をカバー）。
                    for (int ci = 0; ci <= lastNeeded; ci++)
                    {
                        bool inWriteRange = ci >= firstChunk && ci <= lastChunk;
                        bool isExisting = ci < chunkSizes.Count;
                        byte[]? oldStored = isExisting
                            ? await _chunkStore.ReadChunkAsync(volumeName, oldObjectId, ci, ct)
                            : null;
                        if (isExisting && oldStored is null)
                            throw new FileServiceException($"既存チャンク {ci} が見つかりません。");

                        // 新しいオブジェクトへ全チャンクをコピーしてからカタログを切り替える。
                        // 範囲外チャンクは暗号文のままコピーできる。
                        int curPlainSize = (int)Math.Min(chunkSize, newLength - (long)ci * chunkSize);
                        if (!inWriteRange && oldStored is not null && chunkSizes[ci] == curPlainSize)
                        {
                            using var copyStream = new MemoryStream(oldStored, writable: false);
                            await _chunkStore.WriteChunkAsync(volumeName, newObjectId, ci, copyStream, ct);
                            continue;
                        }

                        if (curPlainSize <= 0) break;

                        byte[] plain = new byte[curPlainSize];
                        if (oldStored is not null && chunkSizes[ci] > 0)
                        {
                            int origLen = Math.Min(chunkSizes[ci], curPlainSize);
                            byte[] previous = encrypted
                                ? ChunkEncryptor.DecryptChunkWithScopedKey(masterKey!, patchScopedKey, algorithm, ci, sectorSize, chunkSize, oldStored, origLen)
                                : oldStored;
                            Array.Copy(previous, plain, Math.Min(previous.Length, plain.Length));
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
                            ? ChunkEncryptor.EncryptChunkWithScopedKey(masterKey!, patchScopedKey, algorithm, ci, sectorSize, chunkSize, plain)
                            : plain;
                        using var ms = new MemoryStream(stored);
                        await _chunkStore.WriteChunkAsync(volumeName, newObjectId, ci, ms, ct);

                        while (chunkSizes.Count <= ci) chunkSizes.Add(0);
                        chunkSizes[ci] = curPlainSize;
                    }
                }
                finally
                {
                    if (patchScopedKey is not null)
                        CryptographicOperations.ZeroMemory(patchScopedKey);
                }

                var meta = new FileMetadata
                {
                    Name = fileName,
                    Offset = 0,
                    Length = newLength,
                    ChunkCount = lastNeeded + 1,
                    ChunkSizes = chunkSizes,
                    ChunkObjectId = newObjectId,
                    KeySalt = patchFileSalt is null ? null : Convert.ToBase64String(patchFileSalt),
                    CreatedAt = existing?.CreatedAt ?? DateTimeOffset.UtcNow,
                    ModifiedAt = DateTimeOffset.UtcNow,
                };
                catalog.Files[fileName] = meta;
                await SaveCatalogAsync(volumeName, catalog, ct);
                catalogPublished = true;

                await _journalService.CommitAsync(volumeName, opId, ct);

                if (existing is not null)
                {
                    try { await _chunkStore.DeleteChunksAsync(volumeName, oldObjectId, ct); }
                    catch { /* カタログは新オブジェクトを参照済み。旧世代の削除はベストエフォート。 */ }
                }
                return meta;
            }
            catch
            {
                if (!catalogPublished && newObjectId is not null)
                {
                    try { await _chunkStore.DeleteChunksWithRetryAsync(volumeName, newObjectId, CancellationToken.None); }
                    catch { }
                }
                throw;
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
        string? objectId = null;
        bool catalogPublished = false;
        try
        {
            using var distributedCatalogLock = await AcquireCatalogLockAsync(volumeName, ct);
            var catalog = await LoadCatalogAsync(volumeName, ct);
            catalog.Files.TryGetValue(fileName, out var existing);
            // 新規アップロードは別オブジェクトへ書き込み、カタログ切り替えを
            // 最後に行う。既存ファイルの旧オブジェクトは失敗時も保持する。
            objectId = $"{fileName}.upload-{Guid.NewGuid():N}";

            var chunkSizes = new List<int>();
            byte[] buffer = new byte[chunkSize];
            int chunkIndex = 0;
            long remaining = contentLength;
            int sectorSize = header.EffectiveSectorSize;

            // 新規アップロードでは全チャンクを書き直すため新しいソルトを生成し、
            // ファイルスコープ鍵で別ファイル同一位置チャンクとの tweak 衝突を防ぐ。
            // （チャンクインデックスはファイル相対のためマスターキー直用は衝突する）
            byte[]? uploadFileSalt = header.Encrypted && masterKey is not null
                ? RandomNumberGenerator.GetBytes(16)
                : null;
            // ファイルスコープ鍵はループの前に一度だけ導出する（チャンクごとの HKDF 再導出を避ける）。
            byte[]? uploadScopedKey = uploadFileSalt is null
                ? null
                : ChunkEncryptor.DeriveFileScopedKey(masterKey!, uploadFileSalt, header.EffectiveCipherAlgorithm);

            try
            {
                // 例外パスでも scoped key をゼロクリアする（ループ脱出の全経路をカバー）。
                while (remaining > 0)
                {
                    int toRead = (int)Math.Min(buffer.Length, remaining);
                    // Stream.ReadAsync は EOF 以外でも短く返る。チャンク境界まで集める。
                    int read = await content.ReadAtLeastAsync(buffer.AsMemory(0, toRead), toRead,
                        throwOnEndOfStream: false, ct);
                    if (read != toRead)
                        throw new FileServiceException("リクエスト本文がContent-Lengthより短いです。");

                    byte[] chunkData = buffer[..read].ToArray();

                    // 暗号化ボリュームの場合はチャンク暗号化
                    if (header.Encrypted && masterKey is not null)
                    {
                        chunkData = ChunkEncryptor.EncryptChunkWithScopedKey(
                            masterKey, uploadScopedKey, header.EffectiveCipherAlgorithm,
                            chunkIndex, sectorSize, chunkSize, chunkData);
                    }

                    // S3 にチャンクを保存
                    using var ms = new MemoryStream(chunkData);
                    await _chunkStore.WriteChunkAsync(volumeName, objectId, chunkIndex, ms, ct);

                    chunkSizes.Add(read);
                    chunkIndex++;
                    remaining -= read;
                }
            }
            finally
            {
                if (uploadScopedKey is not null)
                    CryptographicOperations.ZeroMemory(uploadScopedKey);
            }

            var meta = new FileMetadata
            {
                Name = fileName,
                Offset = 0, // チャンクモードでは使用しない
                Length = contentLength,
                ChunkCount = chunkSizes.Count,
                ChunkSizes = chunkSizes,
                ChunkObjectId = objectId,
                KeySalt = uploadFileSalt is null ? null : Convert.ToBase64String(uploadFileSalt),
                CreatedAt = existing?.CreatedAt ?? DateTimeOffset.UtcNow,
                ModifiedAt = DateTimeOffset.UtcNow,
            };
            catalog.Files[fileName] = meta;
            await SaveCatalogAsync(volumeName, catalog, ct);
            catalogPublished = true;

            await _journalService.CommitAsync(volumeName, opId, ct);

            if (existing is not null)
            {
                string oldObjectId = existing.ChunkObjectId ?? fileName;
                try { await _chunkStore.DeleteChunksAsync(volumeName, oldObjectId, ct); }
                catch (Exception) { /* ベストエフォート */ }
            }
            return meta;
        }
        catch
        {
            // カタログ切り替え前に失敗した一時オブジェクトは参照元がなく、
            // ジャーナルからもIDを復元できないため、ここで確実に回収する。
            if (!catalogPublished && objectId is not null)
            {
                try { await _chunkStore.DeleteChunksWithRetryAsync(volumeName, objectId, CancellationToken.None); }
                catch { }
            }
            throw;
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
                    _chunkStore, volumeName, meta.ChunkObjectId ?? fileName, masterKey,
                header.EffectiveCipherAlgorithm,
                sectorSize, chunkSize, meta.ChunkSizes, DecodeKeySalt(meta.KeySalt));
        }
        else
        {
            // 非暗号化: ChunkedReadStream の代わりに MemoryChunkedStream を使用
            chunkedStream = new MemoryChunkedStream(_chunkStore, volumeName, meta.ChunkObjectId ?? fileName, meta.ChunkSizes);
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
            FileMetadata? existing = null;
            await catLock.WaitAsync(ct);
            try
            {
                using var distributedCatalogLock = await AcquireCatalogLockAsync(volumeName, ct);
                var catalog = await LoadCatalogAsync(volumeName, ct);
                if (!catalog.Files.TryGetValue(fileName, out existing)
                    || !catalog.Files.Remove(fileName))
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
                await _chunkStore.DeleteChunksWithRetryAsync(
                    volumeName, existing?.ChunkObjectId ?? fileName, ct);
            }

            await _journalService.CommitAsync(volumeName, opId, ct);
        }

        // 削除後も、待機中のリクエストや同名ファイルの再作成がこのゲートを使う。
        // ここで破棄すると SemaphoreSlim の待機者が永続的に停止したり、
        // 再作成側と古いリクエストが別ゲートで動作する。回収はボリューム削除時に行う。
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
            using var distributedCatalogLock = await AcquireCatalogLockAsync(volumeName, ct);
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
                    // 通信障害・キャンセルは欠損の証拠にならない。
                    // 一覧取得に失敗したらカタログ・ジャーナルを保持したまま復旧を中断する。
                    var indices = await _chunkStore.ListChunksAsync(
                        volumeName, meta.ChunkObjectId ?? fileName, ct);
                    var present = indices.ToHashSet();
                    if (!Enumerable.Range(0, meta.ChunkCount).All(present.Contains))
                        brokenFiles.Add(fileName);
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

    private Task<IDisposable> AcquireCatalogLockAsync(string volumeName, CancellationToken ct)
        => _storage.AcquireLockAsync($"catalog/{Uri.EscapeDataString(volumeName)}", ct);

    /// <summary>FileMetadata.KeySalt (base64) をデコードする。null/不正値はレガシー（ソルトなし）扱い。</summary>
    private static byte[]? DecodeKeySalt(string? keySalt)
    {
        if (string.IsNullOrEmpty(keySalt)) return null;
        try
        {
            byte[] salt = Convert.FromBase64String(keySalt);
            return salt.Length > 0 ? salt : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
