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

    /// <summary>
    /// E2EE 暗号化後のサイズを計算する pure 関数。
    /// 構造: [salt(16)] + [チャンク 0..n-1: 平文 + tag(16)]
    /// 空ファイルでも salt + tag のみで構成される（暗号化時にタグが生成されるため）。
    /// </summary>
    public static long ComputeEncryptedLength(long plainSize, int chunkSize)
    {
        if (plainSize < 0) throw new ArgumentOutOfRangeException(nameof(plainSize));
        if (plainSize > MaxPlainSize) throw new ArgumentOutOfRangeException(nameof(plainSize), $"ファイルサイズは1PB以下である必要があります。");
        if (chunkSize <= 0) throw new ArgumentOutOfRangeException(nameof(chunkSize));
        if (plainSize == 0) return SaltSize + TagSize;
        long chunks = (plainSize + chunkSize - 1) / chunkSize;
        return SaltSize + plainSize + chunks * TagSize;
    }

    private readonly VolumeService _volumeService;
    private readonly IStorageProvider _storage;
    private readonly IChunkStore _chunkStore;
    private readonly string _volumeDataPath;

    /// <summary>ファイル単位の読み書きゲート。ダウンロード中の上書き・削除を防止。</summary>
    private static readonly ConcurrentDictionary<string, AsyncFileGate> _fileGates = new(StringComparer.Ordinal);
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> _volumeGates = new(StringComparer.Ordinal);
    private static readonly ConcurrentDictionary<string, ConcurrentBag<string>> _volumeFileIds = new(StringComparer.Ordinal);

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
    public async Task<E2eeFileEntry> CreateFileAsync(string volumeName, E2eeCreateFileRequest request, string ownerUsername, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);

        var volGate = _volumeGates.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        await volGate.WaitAsync(ct);
        try
        {
            var catalog = await LoadCatalogAsync(volumeName, ct);

            string fileId = Guid.NewGuid().ToString("N");

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
            // 注: ChunkSizes はアップロード後に actual written bytes で更新されるが、
            // CreateFileAsync 段階では EncryptedLength を基数とする。
            // ローカルモードで EncryptedLength が実際の暗号化サイズと一致しない場合は
            // オフセットがずれる可能性がある（UploadChunkAsync 呼び出し前に確定するため）。
            long offset = 0;
            if (!_volumeService.IsChunkMode(volumeName))
            {
                foreach (var existing in catalog.Files.Values)
                {
                    // EncryptedLength を基数としてオフセットを算出（EncryptedLength はチャンク总数+tags）
                    long end = existing.Offset + existing.EncryptedLength;
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
                CreatedAt = DateTimeOffset.UtcNow,
                ModifiedAt = DateTimeOffset.UtcNow,
                OwnerUsername = ownerUsername,
            };

            catalog.Files[fileId] = entry;
            await SaveCatalogAsync(volumeName, catalog, ct);

            _fileGates.TryAdd(fileId, new AsyncFileGate());
            _volumeFileIds.GetOrAdd(volumeName, _ => new ConcurrentBag<string>()).Add(fileId);
            return entry;
        }
        finally
        {
            volGate.Release();
        }
    }

    /// <summary>チャンクをアップロードして volume.dat またはチャンクストアに書き込む。</summary>
    public async Task UploadChunkAsync(string volumeName, string fileId, int chunkIndex, Stream data, long dataLength, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);

        // ボリュームゲート: カタログ R-M-W (catalog-e2ee.json の Load→Modify→Save) を直列化。
        // 旧実装は per-file gate のみで catalog を更新しており、異なる fileId 間の
        // 並行アップロードで catalog 更新が後勝ちで消える競合があった (H-9)。
        var volGate = _volumeGates.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        await volGate.WaitAsync(ct);
        try
        {
            var gate = _fileGates.GetOrAdd(fileId, _ => new AsyncFileGate());
            using (await gate.EnterWriteAsync(ct))
            {
                var catalog = await LoadCatalogAsync(volumeName, ct);

                if (!catalog.Files.TryGetValue(fileId, out var entry))
                    throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");

                if (chunkIndex < 0 || chunkIndex >= entry.ChunkCount)
                    throw new FileServiceException($"チャンクインデックス {chunkIndex} は範囲外です（0-{entry.ChunkCount - 1}）。");

                // 順不同アップロードの厳密検出: 現在のチャンクインデックスが、
                // これまでにアップロード済みのチャンク数と一致しない場合は拒否。
                // 同じ chunkIndex の二重アップロードもここで弾く。
                if (entry.ChunkSizes.Count != chunkIndex)
                    throw new FileServiceException($"チャンク {chunkIndex} は順番にアップロードしてください（期待インデックス: {entry.ChunkSizes.Count}）。");

                // 暗号化チャンクの SHA-256 ハッシュをアップロードと同時に計算
                using var sha = System.Security.Cryptography.IncrementalHash.CreateHash(
                    System.Security.Cryptography.HashAlgorithmName.SHA256);

                if (_volumeService.IsChunkMode(volumeName))
                {
                    // チャンクモード: データを全て読み込んでから書き込み
                    byte[] chunkData = new byte[dataLength];
                    int totalRead = 0;
                    while (totalRead < dataLength)
                    {
                        int read = await data.ReadAsync(chunkData.AsMemory(totalRead, (int)dataLength - totalRead), ct);
                        if (read == 0) break;
                        totalRead += read;
                    }

                    sha.AppendData(chunkData, 0, totalRead);
                    await _chunkStore.WriteChunkAsync(volumeName, fileId, chunkIndex, new MemoryStream(chunkData, 0, totalRead), ct);

                    while (entry.ChunkSizes.Count <= chunkIndex)
                        entry.ChunkSizes.Add(0);
                    entry.ChunkSizes[chunkIndex] = totalRead;
                }
                else
                {
                    long chunkOffset = entry.Offset;
                    for (int i = 0; i < chunkIndex; i++)
                        chunkOffset += entry.ChunkSizes[i];

                    string dataPath = GetDataPath(volumeName);
                    using var fs = new FileStream(dataPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                    fs.Seek(chunkOffset, SeekOrigin.Begin);

                    long written = 0;
                    byte[] buffer = new byte[81920];
                    long remaining = dataLength;
                    while (remaining > 0)
                    {
                        int toRead = (int)Math.Min(buffer.Length, remaining);
                        int read = await data.ReadAsync(buffer.AsMemory(0, toRead), ct);
                        if (read == 0) break;
                        sha.AppendData(buffer, 0, read);
                        await fs.WriteAsync(buffer.AsMemory(0, read), ct);
                        written += read;
                        remaining -= read;
                    }
                    fs.Flush();

                    while (entry.ChunkSizes.Count <= chunkIndex)
                        entry.ChunkSizes.Add(0);
                    entry.ChunkSizes[chunkIndex] = (int)written;
                }

                // ハッシュをカタログに保存
                string hashHex = Convert.ToHexString(sha.GetHashAndReset());
                while (entry.ChunkHashes.Count <= chunkIndex)
                    entry.ChunkHashes.Add("");
                entry.ChunkHashes[chunkIndex] = hashHex;

                await SaveCatalogAsync(volumeName, catalog, ct);
            }
        }
        finally
        {
            volGate.Release();
        }
    }

    /// <summary>チャンクをダウンロード。</summary>
    public async Task<(Stream Stream, long Length)> DownloadChunkAsync(string volumeName, string fileId, int chunkIndex, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);

        var gate = _fileGates.GetOrAdd(fileId, _ => new AsyncFileGate());
        var readLock = await gate.EnterReadAsync(ct);

        try
        {
            var catalog = await LoadCatalogAsync(volumeName, ct);

            if (!catalog.Files.TryGetValue(fileId, out var entry))
                throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");

            if (chunkIndex < 0 || chunkIndex >= entry.ChunkCount)
                throw new FileServiceException($"チャンクインデックス {chunkIndex} は範囲外です。");

            long chunkLength = chunkIndex < entry.ChunkSizes.Count
                ? entry.ChunkSizes[chunkIndex]
                : 0;

            if (_volumeService.IsChunkMode(volumeName))
            {
                byte[]? chunkData = await _chunkStore.ReadChunkAsync(volumeName, fileId, chunkIndex, ct);
                if (chunkData is null)
                    throw new FileServiceException($"チャンク {chunkIndex} が見つかりません。");
                return (new GateReadStream(new MemoryStream(chunkData), readLock), chunkData.Length);
            }

            long chunkOffset = entry.Offset;
            for (int i = 0; i < chunkIndex; i++)
                chunkOffset += entry.ChunkSizes[i];

            string dataPath = GetDataPath(volumeName);
            var fs = new FileStream(dataPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            try
            {
                fs.Seek(chunkOffset, SeekOrigin.Begin);
                return (new GateReadStream(new SubStream(fs, chunkLength), readLock), chunkLength);
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

    /// <summary>チャンクの事前計算ハッシュを返す（カタログ参照のみ、データ読み取りなし）。</summary>
    public async Task<string?> GetChunkHashAsync(string volumeName, string fileId, int chunkIndex, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);

        // ボリュームゲートでカタログ読み取りの整合性を保証
        var volGate = _volumeGates.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        await volGate.WaitAsync(ct);
        try
        {
            var catalog = await LoadCatalogAsync(volumeName, ct);

            if (!catalog.Files.TryGetValue(fileId, out var entry))
                return null;

            if (chunkIndex < 0 || chunkIndex >= entry.ChunkHashes.Count)
                return null;

            string hash = entry.ChunkHashes[chunkIndex];
            return string.IsNullOrEmpty(hash) ? null : hash;
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
            var gate = _fileGates.GetOrAdd(fileId, _ => new AsyncFileGate());
            using (await gate.EnterWriteAsync(ct))
            {
                var catalog = await LoadCatalogAsync(volumeName, ct);
                if (!catalog.Files.TryGetValue(fileId, out var entry))
                    throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");
                entry.EncryptedLength = request.ActualEncryptedLength;
                entry.ModifiedAt = DateTimeOffset.UtcNow;
                await SaveCatalogAsync(volumeName, catalog, ct);
            }
        }
        finally
        {
            volGate.Release();
        }
    }

    /// <summary>ファイル一覧を返す。</summary>
    public async Task<E2eeListFilesResponse> ListFilesAsync(string volumeName, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);
        var catalog = await LoadCatalogAsync(volumeName, ct);

        foreach (var kvp in _fileGates)
        {
            if (!catalog.Files.ContainsKey(kvp.Key))
            {
                if (_fileGates.TryRemove(kvp.Key, out var fileGate))
                    fileGate.Dispose();
            }
        }

        return new E2eeListFilesResponse(catalog.Files.Values.OrderBy(f => f.CreatedAt).ToList());
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
            var gate = _fileGates.GetOrAdd(fileId, _ => new AsyncFileGate());
            using (await gate.EnterWriteAsync(ct))
            {
                var catalog = await LoadCatalogAsync(volumeName, ct);
                if (!catalog.Files.Remove(fileId))
                    throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");
                await SaveCatalogAsync(volumeName, catalog, ct);
            }
        }
        finally
        {
            volGate.Release();
        }

        // チャンクモード: S3 からチャンクを削除（リトライ付き）
        if (isChunkMode)
        {
            await _chunkStore.DeleteChunksWithRetryAsync(volumeName, fileId, ct);
        }

        // ファイル削除後に対応するゲートを破棄
        if (_fileGates.TryRemove(fileId, out var g))
            g.Dispose();
    }

    /// <summary>ボリューム削除時に対応するゲートを破棄。</summary>
    public void CleanupVolumeGates(string volumeName)
    {
        if (_volumeFileIds.TryRemove(volumeName, out var fileIds))
        {
            foreach (var fileId in fileIds)
            {
                if (_fileGates.TryRemove(fileId, out var fileGate))
                    fileGate.Dispose();
            }
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

    private string GetDataPath(string volumeName)
        => Path.Combine(_volumeDataPath, volumeName, "volume.dat");
}
