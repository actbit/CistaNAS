using System.Collections.Concurrent;
using System.Text.Json;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services.Streams;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// E2EE ボリュームのファイル管理。opaque blob として volume.dat に格納し、
/// catalog-e2ee.json に FileId ベースのメタデータを保持する。
/// メタデータは IStorageProvider 経由で保存し、volume.dat はローカルファイルシステムに配置。
/// </summary>
public sealed class E2eeFileService
{
    /// <summary>チャンク先頭に付与される salt のサイズ（バイト）。</summary>
    public const int SaltSize = E2eeCrypto.SaltSize;

    /// <summary>AES-GCM 認証タグのサイズ（バイト）。</summary>
    public const int TagSize = E2eeCrypto.GcmTagSize;

    /// <summary>最大プレーンテキストサイズ（1PB）。整数オーバーフロー防止。</summary>
    public const long MaxPlainSize = 1L << 50; // 1PB = 1,125,899,906,842,624 bytes

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly VolumeService _volumeService;
    private readonly IStorageProvider _storage;
    private readonly IChunkStore _chunkStore;
    private readonly string _volumeDataPath;

    /// <summary>ファイル単位の読み書きゲート。ダウンロード中の上書き・削除を防止。</summary>
    private static readonly ConcurrentDictionary<(string Volume, string FileId), AsyncFileGate> _fileGates = new();
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> _volumeGates = new(StringComparer.Ordinal);

    public E2eeFileService(VolumeService volumeService, IStorageProvider storage, IChunkStore chunkStore, IOptions<CistaNasOptions> options)
    {
        _volumeService = volumeService;
        _storage = storage;
        _chunkStore = chunkStore;
        _volumeDataPath = options.Value.Storage.VolumeDataPath ?? options.Value.DataRoot;
    }

    /// <summary>E2EE ボリュームのヘッダを取得。E2EE でなければ例外。</summary>
    private VolumeHeader GetE2eeHeader(string volumeName)
    {
        var (header, _) = _volumeService.GetMountedKeys(volumeName);
        if (!header.IsE2ee)
            throw new FileServiceException($"ボリューム '{volumeName}' は E2EE ボリュームではありません。");
        return header;
    }

    /// <summary>ファイルエントリを作成し、FileId を返す。</summary>
    public async Task<E2eeFileEntry> CreateFileAsync(string volumeName, E2eeCreateFileRequest request,
        string ownerUsername, CancellationToken ct = default, string? preallocatedFileId = null)
    {
        var header = GetE2eeHeader(volumeName);
        if (request.EncryptedLength < 0 || request.ChunkCount is <= 0 or > 100_000)
            throw new FileServiceException("ファイルサイズまたはチャンク数が不正です。");

        // crypto format v2: KeyEpoch ≥ 1 は共有 v2 形式。ラップ済み DEK が必須で、
        // epoch はボリュームの現行 epoch と一致する（旧 epoch の GroupKey で新規ファイルを作成させない）。
        // KeyEpoch == 0 は v1 形式（単独 E2EE、masterKey 派生 fileKey）。
        if (request.KeyEpoch != header.KeyEpoch)
            throw new FileServiceException($"新規ファイルには現行の KeyEpoch {header.KeyEpoch} が必要です。鍵を再取得してください。");
        if (request.KeyEpoch >= 1)
        {
            if (request.WrappedFileKey is null)
                throw new FileServiceException("KeyEpoch ≥ 1 のファイルには WrappedFileKey が必要です。");
            if (header.GetGroupEpoch(request.KeyEpoch) is null)
                throw new FileServiceException($"GroupKey epoch {request.KeyEpoch} が存在しません。");
            ValidateWrappedFileKeyShape(request.WrappedFileKey);
        }

        long minimumEncryptedLength = checked((long)SaltSize + (long)request.ChunkCount * TagSize);
        long maximumEncryptedLength = checked(minimumEncryptedLength
            + (long)request.ChunkCount * header.ChunkSize);
        if (request.EncryptedLength < minimumEncryptedLength
            || request.EncryptedLength > maximumEncryptedLength)
            throw new FileServiceException("暗号化後ファイルサイズがチャンク構成と一致しません。");

        // ファイルサイズ上限（Volume:MaxFileSizeBytes）。FileService（plain PUT/PATCH）と
        // 同じ不変条件を作成時点でも強制する。
        long plainSize = ComputePlainSize(request.EncryptedLength, request.ChunkCount);
        if (plainSize > _volumeService.MaxFileSizeBytes)
            throw new FileServiceException(
                $"ファイルサイズが上限 ({_volumeService.MaxFileSizeBytes:N0} バイト) を超えています。");

        var volGate = _volumeGates.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        await volGate.WaitAsync(ct);
        try
        {
            using var distributedCatalogLock = await AcquireCatalogLockAsync(volumeName, ct);
            var catalog = await LoadCatalogAsync(volumeName, ct);

            string fileId = preallocatedFileId ?? Guid.NewGuid().ToString("N");
            if (!Guid.TryParseExact(fileId, "N", out var parsedFileId)
                || !string.Equals(fileId, parsedFileId.ToString("N"), StringComparison.Ordinal))
                throw new FileServiceException("fileIdが不正です。");
            if (catalog.Files.ContainsKey(fileId))
                throw new FileServiceException("fileIdが重複しています。");

            // 次のオフセットはカタログから算出する。
            // 旧実装は new FileInfo(dataPath).Length を使っていたが、
            // ボリュームゲート解放後は物理ファイルがまだ空のため
            // 並行 CreateFileAsync で同じ offset が割り当てられて衝突していた。
            //
            // E2EE ボリュームでは:
            //  - ローカルモード (IsChunkMode=false): 各ファイルのチャンクが
            //    volume.dat の Offset から連続して書き込まれる。
            //  - チャンクモード (IsChunkMode=true): チャンクは IChunkStore に格納され
            //    volume.dat は使用されない (Offset 値はメタデータとしてのみ保持)。
            //
            // ローカルモードでは作成時点で物理領域を予約する。EncryptedLength は
            // クライアント申告値であり、実際のチャンク長と異なる可能性があるため、
            // それをそのまま次のファイルの開始位置に使うとファイル同士が重なる。
            long offset = 0;
            if (!_volumeService.IsChunkMode(volumeName))
            {
                foreach (var existing in catalog.Files.Values)
                {
                    long reserved = GetReservedEncryptedLength(header, existing.ChunkCount, existing.EncryptedLength);
                    long end = checked(existing.Offset + reserved);
                    if (end > offset) offset = end;
                }
            }

            var entry = new E2eeFileEntry
            {
                FileId = fileId,
                EncryptedName = request.EncryptedName,
                Offset = offset,
                EncryptedLength = request.EncryptedLength,
                ChunkCount = request.ChunkCount,
                KeyEpoch = request.KeyEpoch,
                WrappedFileKey = request.KeyEpoch >= 1 ? request.WrappedFileKey : null,
                CreatedAt = DateTimeOffset.UtcNow,
                ModifiedAt = DateTimeOffset.UtcNow,
                OwnerUsername = ownerUsername,
            };

            await EnsureQuotaAsync(volumeName, ownerUsername, entry,
                entry.EncryptedLength, entry.ChunkCount, ct);
            catalog.Files[fileId] = entry;
            await SaveCatalogAsync(volumeName, catalog, ct);

            _fileGates.GetOrAdd((volumeName, fileId), _ => new AsyncFileGate());
            return entry;
        }
        finally
        {
            volGate.Release();
        }
    }

    /// <summary>チャンクをアップロードして volume.dat またはチャンクストアに書き込む。</summary>
    public async Task UploadChunkAsync(string volumeName, string fileId, int chunkIndex, Stream data, long dataLength,
        bool replace = false, CancellationToken ct = default, int? encryptionKeyEpoch = null)
    {
        var header = GetE2eeHeader(volumeName);

        // ボリュームゲート: カタログ R-M-W (catalog-e2ee.json の Load→Modify→Save) を直列化。
        // 旧実装は per-file gate のみで catalog を更新しており、異なる fileId 間の
        // 並行アップロードで catalog 更新が後勝ちで消える競合があった (H-9)。
        var volGate = _volumeGates.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        await volGate.WaitAsync(ct);
        try
        {
            using var distributedCatalogLock = await AcquireCatalogLockAsync(volumeName, ct);
            var gate = _fileGates.GetOrAdd((volumeName, fileId), _ => new AsyncFileGate());
            using (await gate.EnterWriteAsync(ct))
            {
                var catalog = await LoadCatalogAsync(volumeName, ct);

                if (!catalog.Files.TryGetValue(fileId, out var entry))
                    throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");

                // Rewrapping changes the DEK's wrap epoch, but an in-flight
                // ciphertext still binds the epoch used when it was encrypted.
                int chunkKeyEpoch = encryptionKeyEpoch ?? entry.KeyEpoch;
                if (entry.KeyEpoch == 0 ? chunkKeyEpoch != 0
                    : chunkKeyEpoch <= 0 || chunkKeyEpoch > header.KeyEpoch || header.GetGroupEpoch(chunkKeyEpoch) is null)
                    throw new FileServiceException("チャンクの暗号化 KeyEpoch が不正です。v2 アップロードには X-Chunk-KeyEpoch が必要です。");

                if (chunkIndex < 0)
                    throw new FileServiceException($"チャンクインデックス {chunkIndex} は範囲外です。");

                // ファイルサイズ上限（Volume:MaxFileSizeBytes）。round 5 ではこの上限が
                // plain 側（FileService）にしかなく、E2EE upload-chunk の replace=true による
                // 末尾追記（chunkIndex == ChunkCount）が無制限にディスクを消費できた（sparse-fill DoS）。
                // 保存済みチャンク長の合計に対して投影後の平文サイズで判定する。
                long storedSoFar = 0;
                for (int i = 0; i < entry.ChunkSizes.Count; i++)
                    storedSoFar = checked(storedSoFar + entry.ChunkSizes[i]);
                // 未確定チャンク（staged visibility の退避分）もストレージを占有するため合算する
                // （二重カウント気味になるが、DoS 防護としては過大評価側に倒すのが安全）。
                if (entry.PendingChunks is not null)
                {
                    foreach (var pending in entry.PendingChunks.Values)
                        storedSoFar = checked(storedSoFar + pending.Size);
                }
                long oldChunkLen = chunkIndex < entry.ChunkSizes.Count ? entry.ChunkSizes[chunkIndex] : 0;
                long projectedStored = Math.Max(0, checked(storedSoFar - oldChunkLen + dataLength));

                // 差分上書き（replace）か新規順次アップロードかで範囲チェックを切替。
                // replace=true: 既存チャンクの上書き、または末尾追記（可視 + 未確定の effective 数まで）を許可。
                //   既存チャンク上書きは nonce の revision を +1 して AES-GCM の nonce 再利用を防ぐ。
                // replace=false: 従来の順次アップロード強制（新規ファイル作成用）。
                //
                // ファイル単位の可視化（staged visibility）: チャンクモードの replace は
                // PendingChunks に退避され、FinalizeFileAsync の一括昇格で初めて読み取り側に見える。
                // 排他の単位をチャンクでなくファイルにするため（昇格はカタログ R-M-W 1 回で完了し、
                // 複数チャンク差し替え中の読み手が新旧混在のファイルを読めない）。
                // 範囲チェックは可視 ChunkCount と未確定最大インデックスの effective 数に対して行う。
                int effectiveChunkCount = entry.ChunkCount;
                if (entry.PendingChunks is not null)
                {
                    foreach (int pendingIndex in entry.PendingChunks.Keys)
                        effectiveChunkCount = Math.Max(effectiveChunkCount, pendingIndex + 1);
                }
                int projectedChunkCount = Math.Max(effectiveChunkCount, replace ? chunkIndex + 1 : effectiveChunkCount);
                long projectedPlain = ComputePlainSize(projectedStored, projectedChunkCount);
                if (projectedPlain > _volumeService.MaxFileSizeBytes)
                    throw new FileServiceException(
                        $"ファイルサイズが上限 ({_volumeService.MaxFileSizeBytes:N0} バイト) を超えています。");

                if (replace)
                {
                    if (chunkIndex > effectiveChunkCount)
                        throw new FileServiceException($"チャンク {chunkIndex} は範囲外です（差分上書きは 0-{effectiveChunkCount}）。");
                }
                else
                {
                    if (chunkIndex >= entry.ChunkCount)
                        throw new FileServiceException($"チャンクインデックス {chunkIndex} は範囲外です（0-{entry.ChunkCount - 1}）。");

                    // 順不同アップロードの厳密検出: 現在のチャンクインデックスが、
                    // これまでにアップロード済みのチャンク数と一致しない場合は拒否。
                    // 同じ chunkIndex の二重アップロードもここで弾く。
                    if (entry.ChunkSizes.Count != chunkIndex)
                        throw new FileServiceException($"チャンク {chunkIndex} は順番にアップロードしてください（期待インデックス: {entry.ChunkSizes.Count}）。");
                }

                // Content-Length（クライアント設定で信頼できない）による巨大バッファ割り当て DoS を防ぐ。
                // E2EE チャンクの暗号文 = 平文チャンク + salt(16, 先頭のみ) + tag(16) + 余裕。
                long maxEncChunkBytes = (long)header.ChunkSize + TagSize
                    + (chunkIndex == 0 ? SaltSize : 0);
                if (dataLength < 0 || dataLength > maxEncChunkBytes)
                    throw new FileServiceException($"チャンクデータ長 ({dataLength}) が上限 ({maxEncChunkBytes} バイト) を超えています。");

                byte[] chunkData = new byte[checked((int)dataLength)];
                int totalRead = 0;
                while (totalRead < chunkData.Length)
                {
                    int read = await data.ReadAsync(chunkData.AsMemory(totalRead), ct);
                    if (read == 0) break;
                    totalRead += read;
                }
                if (totalRead != chunkData.Length)
                    throw new FileServiceException("リクエスト本文がContent-Lengthより短いです。");

                string hashHex = Convert.ToHexString(
                    System.Security.Cryptography.SHA256.HashData(chunkData));

                string? newChunkObjectId = null;

                if (_volumeService.IsChunkMode(volumeName))
                {
                    newChunkObjectId = $"{fileId}/versions/{Guid.NewGuid():N}";
                    using var chunkStream = new MemoryStream(chunkData, writable: false);
                    await _chunkStore.WriteChunkAsync(volumeName, newChunkObjectId, chunkIndex, chunkStream, ct);
                }
                else
                {
                    long chunkOffset = entry.Offset;
                    for (int i = 0; i < chunkIndex; i++)
                        chunkOffset += i < entry.ChunkSizes.Count ? entry.ChunkSizes[i] : 0;

                    string dataPath = GetDataPath(volumeName);
                    using var fs = new FileStream(dataPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                    fs.Seek(chunkOffset, SeekOrigin.Begin);
                    await fs.WriteAsync(chunkData, ct);
                    await fs.FlushAsync(ct);
                }

                // revision: 「実際にアップロード済みのチャンク」の差分上書きは nonce を一意にする
                // ため +1。未アップロード（宣言のみ・hash 未記録）のチャンクへの初回書き込みは
                // revision=0 のまま — クライアントは GetChunkHash の hash が null のとき
                // revision=0 で暗号化するため、サーバーの記録と一致させる（旧実装は
                // 「chunkIndex < ChunkCount」で判定していたため、sparse 書き込みで宣言済み
                // 未アップロード・チャンクに replace=true した場合にサーバーだけ +1 して
                // 復号不能になる潜在バグがあった）。同一未確定チャンクの再上書きでも
                // pending 側の revision から連続して増えるため nonce 再利用は起こらない。
                bool previouslyUploaded = (entry.PendingChunks is not null && entry.PendingChunks.ContainsKey(chunkIndex))
                    || (chunkIndex < entry.ChunkHashes.Count && !string.IsNullOrEmpty(entry.ChunkHashes[chunkIndex]));
                int newRevision;
                if (replace && previouslyUploaded)
                {
                    int baseRevision = entry.PendingChunks is not null && entry.PendingChunks.TryGetValue(chunkIndex, out var existingPending)
                        ? existingPending.Revision
                        : chunkIndex < entry.ChunkRevisions.Count ? entry.ChunkRevisions[chunkIndex] : 0;
                    newRevision = baseRevision + 1;
                }
                else
                {
                    newRevision = 0; // 新規 / 末尾追記 / 未アップロード・チャンクへの初回書き込み
                }

                if (replace && newChunkObjectId is not null)
                {
                    // チャンクモードの差分上書き: ファイル単位の可視化（staged visibility）。
                    // 未確定チャンクとして PendingChunks に退避し、可視カタログ
                    // （ChunkObjectIds / Sizes / Hashes / Revisions / KeyEpochs / ChunkCount）は
                    // 一切更新しない。FinalizeFileAsync の一括昇格で初めて読み取り側に見えるため、
                    // 複数チャンクの差し替え中でも読み手は常に完全な旧バージョンを見る。
                    // 旧チャンクオブジェクトも昇格まで保持する（中途半端な状態で公開しない）。
                    // 新規順次アップロード（replace=false）は従来通り即時反映する
                    //（半完成の新ファイルは確定まで読めない方が自然だが、既存クライアントの
                    // アップロード途中リスト取得・レジューム動作を変えないため）。
                    entry.PendingChunks ??= [];
                    entry.PendingChunks[chunkIndex] = new E2eePendingChunk
                    {
                        ObjectId = newChunkObjectId,
                        Size = chunkData.Length,
                        Hash = hashHex,
                        Revision = newRevision,
                        KeyEpoch = chunkKeyEpoch,
                    };
                }
                else
                {
                    // 非チャンクモード（レガシー・共有 volume.dat への in-place 書き込み）と
                    // 新規順次アップロードは staging できない / しないため、従来通り即時反映する。
                    // 書き込みセッション間の排他は E2eeWriteLeaseService のファイル単位リースで
                    // 保証される。crypto format v2: チャンクを暗号化したときの keyEpoch を記録する。
                    if (chunkIndex == entry.ChunkCount)
                        entry.ChunkCount = chunkIndex + 1; // 末尾追記: チャンクを拡張
                    while (entry.ChunkSizes.Count <= chunkIndex)
                        entry.ChunkSizes.Add(0);
                    entry.ChunkSizes[chunkIndex] = chunkData.Length;

                    while (entry.ChunkHashes.Count <= chunkIndex)
                        entry.ChunkHashes.Add("");
                    entry.ChunkHashes[chunkIndex] = hashHex;

                    while (entry.ChunkRevisions.Count <= chunkIndex)
                        entry.ChunkRevisions.Add(0);
                    entry.ChunkRevisions[chunkIndex] = newRevision;

                    while (entry.ChunkKeyEpochs.Count <= chunkIndex)
                        entry.ChunkKeyEpochs.Add(entry.KeyEpoch);
                    entry.ChunkKeyEpochs[chunkIndex] = chunkKeyEpoch;

                    if (newChunkObjectId is not null)
                    {
                        while (entry.ChunkObjectIds.Count <= chunkIndex)
                            entry.ChunkObjectIds.Add("");
                        entry.ChunkObjectIds[chunkIndex] = newChunkObjectId;
                    }
                }

                try
                {
                    await SaveCatalogAsync(volumeName, catalog, ct);
                }
                catch
                {
                    // カタログ保存失敗時は未確定チャンクの新オブジェクトを撤去（ゴミを残さない）。
                    // 可視カタログは更新していないため、既存データは無傷のまま。
                    if (newChunkObjectId is not null)
                    {
                        try { await _chunkStore.DeleteChunksWithRetryAsync(volumeName, newChunkObjectId, CancellationToken.None); }
                        catch { }
                    }
                    throw;
                }
            }
        }
        finally
        {
            volGate.Release();
        }
    }

    /// <summary>チャンクをダウンロード。revision と（v2 の場合）暗号化時の keyEpoch を返す。</summary>
    public async Task<(Stream Stream, long Length, int Revision, int KeyEpoch)> DownloadChunkAsync(string volumeName, string fileId, int chunkIndex, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);

        var gate = _fileGates.GetOrAdd((volumeName, fileId), _ => new AsyncFileGate());
        var readLock = await gate.EnterReadAsync(ct);

        try
        {
            var catalog = await LoadCatalogAsync(volumeName, ct);

            if (!catalog.Files.TryGetValue(fileId, out var entry))
                throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");

            if (chunkIndex < 0 || chunkIndex >= entry.ChunkCount)
                throw new FileServiceException($"チャンクインデックス {chunkIndex} は範囲外です。");

            int revision = chunkIndex < entry.ChunkRevisions.Count ? entry.ChunkRevisions[chunkIndex] : 0;
            int keyEpoch = chunkIndex < entry.ChunkKeyEpochs.Count ? entry.ChunkKeyEpochs[chunkIndex] : entry.KeyEpoch;

            long chunkLength = chunkIndex < entry.ChunkSizes.Count
                ? entry.ChunkSizes[chunkIndex]
                : 0;

            if (_volumeService.IsChunkMode(volumeName))
            {
                string chunkObjectId = GetChunkObjectId(entry, chunkIndex);
                byte[]? chunkData = await _chunkStore.ReadChunkAsync(volumeName, chunkObjectId, chunkIndex, ct);
                if (chunkData is null)
                    throw new FileServiceException($"チャンク {chunkIndex} が見つかりません。");
                return (new GateReadStream(new MemoryStream(chunkData), readLock), chunkData.Length, revision, keyEpoch);
            }

            long chunkOffset = entry.Offset;
            for (int i = 0; i < chunkIndex; i++)
                chunkOffset += i < entry.ChunkSizes.Count ? entry.ChunkSizes[i] : 0;

            string dataPath = GetDataPath(volumeName);
            var fs = new FileStream(dataPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            try
            {
                fs.Seek(chunkOffset, SeekOrigin.Begin);
                return (new GateReadStream(new SubStream(fs, chunkLength), readLock), chunkLength, revision, keyEpoch);
            }
            catch
            {
                fs.Dispose();
                throw;
            }
        }
        catch
        {
            readLock.Dispose();
            throw;
        }
    }

    /// <summary>チャンクの事前計算ハッシュと revision を返す（カタログ参照のみ、データ読み取りなし）。</summary>
    public async Task<(string? Hash, int Revision)> GetChunkHashAsync(string volumeName, string fileId, int chunkIndex, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);

        // ボリュームゲートでカタログ読み取りの整合性を保証
        var volGate = _volumeGates.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        await volGate.WaitAsync(ct);
        try
        {
            var catalog = await LoadCatalogAsync(volumeName, ct);

            if (!catalog.Files.TryGetValue(fileId, out var entry))
                return (null, 0);

            if (chunkIndex < 0)
                return (null, 0);

            // 未確定チャンク（staged visibility の退避分）は確定前の検証（GetChunkHash → 暗号化 →
            // UploadChunk → Finalize）で参照されるため、effective ビュー（pending 優先）で返す。
            // DownloadChunkAsync は可視チャンクのみを返すため、確定前のデータが読めることはない。
            if (entry.PendingChunks is not null && entry.PendingChunks.TryGetValue(chunkIndex, out var pending))
                return (pending.Hash, pending.Revision);

            if (chunkIndex >= entry.ChunkHashes.Count)
                return (null, 0);

            string hash = entry.ChunkHashes[chunkIndex];
            int revision = chunkIndex < entry.ChunkRevisions.Count ? entry.ChunkRevisions[chunkIndex] : 0;
            return string.IsNullOrEmpty(hash) ? (null, 0) : (hash, revision);
        }
        finally
        {
            volGate.Release();
        }
    }

    /// <summary>アップロード完了を確定。</summary>
    public async Task FinalizeFileAsync(string volumeName, string fileId, E2eeFinalizeFileRequest request, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);
        // ボリュームゲートでカタログ R-M-W を直列化 (H-9)
        var volGate = _volumeGates.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        await volGate.WaitAsync(ct);
        try
        {
            using var distributedCatalogLock = await AcquireCatalogLockAsync(volumeName, ct);
            var gate = _fileGates.GetOrAdd((volumeName, fileId), _ => new AsyncFileGate());
            using (await gate.EnterWriteAsync(ct))
            {
                var catalog = await LoadCatalogAsync(volumeName, ct);
                if (!catalog.Files.TryGetValue(fileId, out var entry))
                    throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");

                // ファイル単位の可視化: 未確定チャンク（replace 分）をここで一括昇格する。
                // 昇格はカタログ R-M-W 1 回で完了するため、読み手は常に完全な旧版か完全な新版の
                // どちらかを見る（チャンク単位の断片公開がない）。昇格前の可視 ObjectId は
                // 検証成功後（SaveCatalogAsync 後）にベストエフォートで削除する。検証失敗時は
                // 保存しないため未確定チャンクと旧データは無傷 — クライアントは再確定または
                // ファイル削除で回復できる。
                List<string> removedObjectIds = [];
                if (entry.PendingChunks is { Count: > 0 })
                {
                    foreach (var (pendingIndex, pending) in entry.PendingChunks)
                    {
                        string? oldObjectId = pendingIndex < entry.ChunkObjectIds.Count ? entry.ChunkObjectIds[pendingIndex] : null;
                        while (entry.ChunkObjectIds.Count <= pendingIndex) entry.ChunkObjectIds.Add("");
                        while (entry.ChunkSizes.Count <= pendingIndex) entry.ChunkSizes.Add(0);
                        while (entry.ChunkHashes.Count <= pendingIndex) entry.ChunkHashes.Add("");
                        while (entry.ChunkRevisions.Count <= pendingIndex) entry.ChunkRevisions.Add(0);
                        while (entry.ChunkKeyEpochs.Count <= pendingIndex) entry.ChunkKeyEpochs.Add(pending.KeyEpoch);

                        if (!string.IsNullOrWhiteSpace(oldObjectId) && oldObjectId != fileId && oldObjectId != pending.ObjectId)
                            removedObjectIds.Add(oldObjectId);

                        entry.ChunkObjectIds[pendingIndex] = pending.ObjectId;
                        entry.ChunkSizes[pendingIndex] = pending.Size;
                        entry.ChunkHashes[pendingIndex] = pending.Hash;
                        entry.ChunkRevisions[pendingIndex] = pending.Revision;
                        entry.ChunkKeyEpochs[pendingIndex] = pending.KeyEpoch;
                    }
                    entry.ChunkCount = Math.Max(entry.ChunkCount, entry.PendingChunks.Keys.Max() + 1);
                    entry.PendingChunks = null;
                }

                int requestedChunkCount = request.ChunkCount ?? entry.ChunkCount;
                if (requestedChunkCount <= 0 || requestedChunkCount > entry.ChunkCount
                    || entry.ChunkSizes.Count < requestedChunkCount)
                    throw new FileServiceException("チャンク数が不正です。");
                long actualStoredLength = 0;
                for (int i = 0; i < requestedChunkCount; i++)
                    actualStoredLength = checked(actualStoredLength + entry.ChunkSizes[i]);
                if (request.ActualEncryptedLength != actualStoredLength)
                    throw new FileServiceException("暗号化後ファイルサイズが保存済みチャンク長と一致しません。");
                long plainLength = ComputePlainSize(actualStoredLength, requestedChunkCount);
                if (plainLength > MaxPlainSize)
                    throw new FileServiceException("ファイルサイズは1PB以下である必要があります。");
                await EnsureQuotaAsync(volumeName, entry.OwnerUsername, entry,
                    actualStoredLength, requestedChunkCount, ct);
                entry.EncryptedLength = actualStoredLength;
                entry.ModifiedAt = DateTimeOffset.UtcNow;

                // ファイル長変更（縮小）時のチャンク数調整（論理切り詰め）。
                // チャンクモードの物理チャンク削除はベストエフォート（カタログ整合性を優先）。
                if (request.ChunkCount is int newCc && newCc >= 0 && newCc < entry.ChunkCount)
                {
                    for (int i = newCc; i < entry.ChunkObjectIds.Count; i++)
                    {
                        string objectId = entry.ChunkObjectIds[i];
                        if (!string.IsNullOrWhiteSpace(objectId) && objectId != fileId)
                            removedObjectIds.Add(objectId);
                    }
                    entry.ChunkCount = newCc;
                    if (entry.ChunkSizes.Count > newCc) entry.ChunkSizes.RemoveRange(newCc, entry.ChunkSizes.Count - newCc);
                    if (entry.ChunkHashes.Count > newCc) entry.ChunkHashes.RemoveRange(newCc, entry.ChunkHashes.Count - newCc);
                    if (entry.ChunkRevisions.Count > newCc) entry.ChunkRevisions.RemoveRange(newCc, entry.ChunkRevisions.Count - newCc);
                    if (entry.ChunkObjectIds.Count > newCc) entry.ChunkObjectIds.RemoveRange(newCc, entry.ChunkObjectIds.Count - newCc);
                }

                await SaveCatalogAsync(volumeName, catalog, ct);

                foreach (string objectId in removedObjectIds.Distinct(StringComparer.Ordinal))
                {
                    try { await _chunkStore.DeleteChunksAsync(volumeName, objectId, ct); }
                    catch { /* 切り詰めは公開済み。旧世代の削除はベストエフォート。 */ }
                }
            }
        }
        finally
        {
            volGate.Release();
        }
    }

    /// <summary>
    /// crypto format v2: ファイル鍵を新しい GroupKey epoch に再ラップする（GroupKey ローテーション後の
    /// epoch migration / 更新時 migration）。チャンク本体は不変 — WrappedFileKey と KeyEpoch のみ更新。
    /// オーナーまたは現行メンバーがクライアント側で DEK をアンラップ → 新 epoch の GroupKey で再ラップして送信。
    /// </summary>
    public async Task RewrapFileKeysAsync(string volumeName, E2eeRewrapFileKeysRequest request, string requesterUsername, CancellationToken ct = default)
    {
        var header = GetE2eeHeader(volumeName);
        if (string.IsNullOrEmpty(header.VolumeId))
            throw new FileServiceException("このボリュームは共有 v2 形式に移行されていません。");
        if (!header.HasUserAccess(requesterUsername))
            throw new FileServiceException("このボリュームへのアクセス権がありません。");

        var volGate = _volumeGates.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        await volGate.WaitAsync(ct);
        try
        {
            using var distributedCatalogLock = await AcquireCatalogLockAsync(volumeName, ct);
            var catalog = await LoadCatalogAsync(volumeName, ct);
            foreach (var rewrap in request.Rewraps)
            {
                if (!catalog.Files.TryGetValue(rewrap.FileId, out var entry))
                    throw new FileServiceException($"ファイル '{rewrap.FileId}' が見つかりません。");
                if (entry.KeyEpoch == 0)
                    throw new FileServiceException("v1 ファイルは鍵の再ラップだけでは v2 形式に変換できません。");
                // 再ラップ先 epoch は現行 epoch のみ（旧 epoch への巻き戻しを防止）。
                if (rewrap.KeyEpoch != header.KeyEpoch || header.GetGroupEpoch(rewrap.KeyEpoch) is null)
                    throw new FileServiceException($"KeyEpoch {rewrap.KeyEpoch} は不正です（現行: {header.KeyEpoch}）。");
                if (rewrap.KeyEpoch < entry.KeyEpoch)
                    throw new FileServiceException($"ファイル '{rewrap.FileId}' の KeyEpoch を巻き戻せません。");
                ValidateWrappedFileKeyShape(rewrap.WrappedFileKey);

                // Older catalogs infer missing chunk epochs from the file's
                // wrap epoch. Materialize that value before changing the wrap.
                while (entry.ChunkKeyEpochs.Count < entry.ChunkCount)
                    entry.ChunkKeyEpochs.Add(entry.KeyEpoch);
                entry.KeyEpoch = rewrap.KeyEpoch;
                entry.WrappedFileKey = rewrap.WrappedFileKey;
            }
            await SaveCatalogAsync(volumeName, catalog, ct);
        }
        finally
        {
            volGate.Release();
        }
    }

    /// <summary>WrappedFileKey の形状検証（algorithm / サイズ）。</summary>
    private static void ValidateWrappedFileKeyShape(VolumeHeader.WrappedKey wrapped)
    {
        if (!string.Equals(wrapped.Algorithm, "aes-256-gcm", StringComparison.Ordinal))
            throw new FileServiceException("WrappedFileKey のアルゴリズムは aes-256-gcm のみサポートです。");
        if (wrapped.Nonce.Length != E2eeCrypto.GcmNonceSize)
            throw new FileServiceException("WrappedFileKey の nonce サイズが不正です。");
        if (wrapped.Ciphertext.Length != E2eeCrypto.MasterKeySize)
            throw new FileServiceException("WrappedFileKey の ciphertext サイズが不正です。");
        if (wrapped.Tag.Length != E2eeCrypto.GcmTagSize)
            throw new FileServiceException("WrappedFileKey の tag サイズが不正です。");
    }

    private static long GetReservedEncryptedLength(VolumeHeader header, int chunkCount, long declaredLength)
    {
        if (chunkCount < 0) throw new FileServiceException("チャンク数が不正です。");
        long capacity = checked((long)SaltSize + (long)chunkCount * (header.ChunkSize + TagSize));
        return Math.Max(capacity, declaredLength);
    }

    private static string GetChunkObjectId(E2eeFileEntry entry, int chunkIndex)
        => chunkIndex < entry.ChunkObjectIds.Count && !string.IsNullOrWhiteSpace(entry.ChunkObjectIds[chunkIndex])
            ? entry.ChunkObjectIds[chunkIndex]
            : entry.FileId;

    private async Task EnsureQuotaAsync(string volumeName, string username, E2eeFileEntry current,
        long encryptedLength, int chunkCount, CancellationToken ct)
    {
        var (header, _) = _volumeService.GetMounted(volumeName);
        if (!header.UserQuotas.TryGetValue(username, out var quota) || quota <= 0)
            return;

        var catalog = await LoadCatalogAsync(volumeName, ct);
        long used = 0;
        foreach (var entry in catalog.Files.Values)
        {
            if (entry.FileId == current.FileId) continue;
            if (entry.OwnerUsername == username || string.IsNullOrEmpty(entry.OwnerUsername))
                used = checked(used + ComputePlainSize(entry.EncryptedLength, entry.ChunkCount));
        }

        long requested = ComputePlainSize(encryptedLength, chunkCount);
        if (checked(used + requested) > quota)
            throw new FileServiceException("ユーザーのクォータを超えています。");
    }

    /// <summary>ファイル一覧を返す。</summary>
    public async Task<E2eeListFilesResponse> ListFilesAsync(string volumeName, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);
        var catalog = await LoadCatalogAsync(volumeName, ct);

        // Catalog absence does not mean a gate is idle: deletion and queued
        // downloads may still own it. Retain gates until volume cleanup so a
        // recreated file ID and older requests continue sharing the same gate.
        return new E2eeListFilesResponse(catalog.Files.Values.OrderBy(f => f.CreatedAt).ToList());
    }

    /// <summary>指定した E2EE ファイルIDが現在のカタログに存在するか確認する。</summary>
    public async Task<bool> ExistsAsync(string volumeName, string fileId, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);
        var catalog = await LoadCatalogAsync(volumeName, ct);
        return catalog.Files.ContainsKey(fileId);
    }

    /// <summary>ファイルを削除。</summary>
    public async Task DeleteFileAsync(string volumeName, string fileId, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);
        bool isChunkMode = _volumeService.IsChunkMode(volumeName);
        // ボリュームゲートでカタログ R-M-W を直列化 (H-9)
        var volGate = _volumeGates.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        await volGate.WaitAsync(ct);
        try
        {
            using var distributedCatalogLock = await AcquireCatalogLockAsync(volumeName, ct);
            var gate = _fileGates.GetOrAdd((volumeName, fileId), _ => new AsyncFileGate());
            using (await gate.EnterWriteAsync(ct))
            {
                var catalog = await LoadCatalogAsync(volumeName, ct);
                if (!catalog.Files.Remove(fileId))
                    throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");
                await SaveCatalogAsync(volumeName, catalog, ct);

                // Prefix deletion includes all chunk generations under this ID.
                // Keep both locks until it finishes; otherwise a new creation
                // can upload chunks that this older deletion then removes.
                if (isChunkMode)
                    await _chunkStore.DeleteChunksWithRetryAsync(volumeName, fileId, ct);
            }
        }
        finally
        {
            volGate.Release();
        }
    }

    /// <summary>ボリューム削除時に対応するゲートを破棄。</summary>
    public void CleanupVolumeGates(string volumeName)
    {
        foreach (var key in _fileGates.Keys.Where(key => key.Volume == volumeName))
        {
            if (_fileGates.TryRemove(key, out var fileGate))
                fileGate.Dispose();
        }

        if (_volumeGates.TryRemove(volumeName, out var volGate))
            volGate.Dispose();
    }

    /// <summary>E2EE マウント情報を返す。</summary>
    public E2eeMountResponse GetMountInfo(string volumeName)
    {
        var header = GetE2eeHeader(volumeName);
        return new E2eeMountResponse(header.ChunkSize, header.EncryptionMode);
    }

    /// <summary>平文サイズを計算する（E2EE 暗号化フォーマット対応）。</summary>
    public static long ComputePlainSize(long encryptedLength, int chunkCount)
    {
        // フォーマット: salt(16) + [chunk0: ciphertext + tag(16) | ... | chunkN-1: ciphertext + tag(16)]
        // ciphertext = チャンクサイズ（最後のチャンクは実際のサイズ）
        // 平文 = encrypted - salt - chunkCount * tag
        long plain = encryptedLength - (long)SaltSize - (long)chunkCount * (long)TagSize;
        return Math.Max(0, plain);
    }

    /// <summary>ボリュームの使用量統計を返す。</summary>
    public async Task<E2eeVolumeStats> GetStatsAsync(string volumeName, string username, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);
        var catalog = await LoadCatalogAsync(volumeName, ct);
        var (header, _) = _volumeService.GetMounted(volumeName);

        long totalUsed = catalog.Files.Values.Sum(f => ComputePlainSize(f.EncryptedLength, f.ChunkCount));
        long userUsed = catalog.Files.Values
            .Where(f => f.OwnerUsername == username || string.IsNullOrEmpty(f.OwnerUsername))
            .Sum(f => ComputePlainSize(f.EncryptedLength, f.ChunkCount));
        long quota = header.UserQuotas.TryGetValue(username, out var q) ? q : 0;
        int totalFiles = catalog.Files.Count;
        int userFiles = catalog.Files.Values
            .Count(f => f.OwnerUsername == username || string.IsNullOrEmpty(f.OwnerUsername));

        return new E2eeVolumeStats(totalUsed, userUsed, quota, totalFiles, userFiles);
    }

    // ---- 内部ヘルパー ----

    private async Task<E2eeCatalog> LoadCatalogAsync(string volumeName, CancellationToken ct)
    {
        byte[]? data = await _storage.ReadAsync($"{volumeName}/catalog-e2ee.json", ct);
        if (data is null) return new E2eeCatalog();
        return JsonSerializer.Deserialize<E2eeCatalog>(data, JsonOptions) ?? new E2eeCatalog();
    }

    private async Task SaveCatalogAsync(string volumeName, E2eeCatalog catalog, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        JsonSerializer.Serialize(ms, catalog, JsonOptions);
        ms.Position = 0;
        await _storage.WriteAtomicAsync($"{volumeName}/catalog-e2ee.json", ms, ct);
    }

    private Task<IDisposable> AcquireCatalogLockAsync(string volumeName, CancellationToken ct)
        => _storage.AcquireLockAsync($"catalog-e2ee/{Uri.EscapeDataString(volumeName)}", ct);

    private string GetDataPath(string volumeName)
        => Path.Combine(_volumeDataPath, volumeName, "volume.dat");
}
