using System.Collections.Concurrent;
using System.Text.Json;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
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
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly VolumeService _volumeService;
    private readonly IStorageProvider _storage;
    private readonly IChunkStore _chunkStore;
    private readonly string _volumeDataPath;

    private static readonly ConcurrentDictionary<string, SemaphoreSlim> _fileGates = new(StringComparer.Ordinal);
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

    /// <summary>ボリュームがチャンクストレージモードか。</summary>
    private bool IsChunkMode(string volumeName)
    {
        var (header, _) = _volumeService.GetMountedKeys(volumeName);
        return header.StorageMode == "chunk";
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
            string dataPath = GetDataPath(volumeName);
            long offset = new FileInfo(dataPath).Length;

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

            _fileGates.TryAdd(fileId, new SemaphoreSlim(1, 1));
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

        var gate = _fileGates.GetOrAdd(fileId, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            var catalog = await LoadCatalogAsync(volumeName, ct);

            if (!catalog.Files.TryGetValue(fileId, out var entry))
                throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");

            if (chunkIndex < 0 || chunkIndex >= entry.ChunkCount)
                throw new FileServiceException($"チャンクインデックス {chunkIndex} は範囲外です（0-{entry.ChunkCount - 1}）。");

            // 順不同アップロードの検出: 前のチャンクが未完了なら拒否
            if (chunkIndex > 0 && entry.ChunkSizes.Count < chunkIndex)
                throw new FileServiceException($"チャンク {chunkIndex - 1} が未アップロードです。順番にアップロードしてください。");

            if (IsChunkMode(volumeName))
            {
                await _chunkStore.WriteChunkAsync(volumeName, fileId, chunkIndex, data, ct);

                while (entry.ChunkSizes.Count <= chunkIndex)
                    entry.ChunkSizes.Add(0);
                entry.ChunkSizes[chunkIndex] = (int)dataLength;
            }
            else
            {
                long chunkOffset = entry.Offset;
                for (int i = 0; i < chunkIndex; i++)
                    chunkOffset += entry.ChunkSizes[i];

                // ボリュームゲートで volume.dat への書き込みを直列化
                var volGate = _volumeGates.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
                await volGate.WaitAsync(ct);
                long written;
                try
                {
                    string dataPath = GetDataPath(volumeName);
                    using var fs = new FileStream(dataPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                    fs.Seek(chunkOffset, SeekOrigin.Begin);

                    written = 0;
                    byte[] buffer = new byte[81920];
                    long remaining = dataLength;
                    while (remaining > 0)
                    {
                        int toRead = (int)Math.Min(buffer.Length, remaining);
                        int read = await data.ReadAsync(buffer.AsMemory(0, toRead), ct);
                        if (read == 0) break;
                        fs.Write(buffer, 0, read);
                        written += read;
                        remaining -= read;
                    }
                    fs.Flush();
                }
                finally
                {
                    volGate.Release();
                }

                while (entry.ChunkSizes.Count <= chunkIndex)
                    entry.ChunkSizes.Add(0);
                entry.ChunkSizes[chunkIndex] = (int)written;
            }

            await SaveCatalogAsync(volumeName, catalog, ct);
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>チャンクをダウンロード。</summary>
    public async Task<(Stream Stream, long Length)> DownloadChunkAsync(string volumeName, string fileId, int chunkIndex, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);
        var catalog = await LoadCatalogAsync(volumeName, ct);

        if (!catalog.Files.TryGetValue(fileId, out var entry))
            throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");

        if (chunkIndex < 0 || chunkIndex >= entry.ChunkCount)
            throw new FileServiceException($"チャンクインデックス {chunkIndex} は範囲外です。");

        long chunkLength = chunkIndex < entry.ChunkSizes.Count
            ? entry.ChunkSizes[chunkIndex]
            : 0;

        if (IsChunkMode(volumeName))
        {
            byte[]? chunkData = await _chunkStore.ReadChunkAsync(volumeName, fileId, chunkIndex, ct);
            if (chunkData is null)
                throw new FileServiceException($"チャンク {chunkIndex} が見つかりません。");
            return (new MemoryStream(chunkData), chunkData.Length);
        }

        long chunkOffset = entry.Offset;
        for (int i = 0; i < chunkIndex; i++)
            chunkOffset += entry.ChunkSizes[i];

        string dataPath = GetDataPath(volumeName);
        var fs = new FileStream(dataPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        try
        {
            fs.Seek(chunkOffset, SeekOrigin.Begin);
            return (new SubStream(fs, chunkLength), chunkLength);
        }
        catch
        {
            fs.Dispose();
            throw;
        }
    }

    /// <summary>アップロード完了を確定。</summary>
    public async Task FinalizeFileAsync(string volumeName, string fileId, E2eeFinalizeFileRequest request, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);
        var gate = _fileGates.GetOrAdd(fileId, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            var catalog = await LoadCatalogAsync(volumeName, ct);
            if (!catalog.Files.TryGetValue(fileId, out var entry))
                throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");
            entry.EncryptedLength = request.ActualEncryptedLength;
            entry.ModifiedAt = DateTimeOffset.UtcNow;
            await SaveCatalogAsync(volumeName, catalog, ct);
        }
        finally
        {
            gate.Release();
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
                if (_fileGates.TryRemove(kvp.Key, out var gate))
                    gate.Dispose();
            }
        }

        return new E2eeListFilesResponse(catalog.Files.Values.OrderBy(f => f.CreatedAt).ToList());
    }

    /// <summary>ファイルを削除。</summary>
    public async Task DeleteFileAsync(string volumeName, string fileId, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);
        bool isChunkMode = IsChunkMode(volumeName);
        var gate = _fileGates.GetOrAdd(fileId, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            var catalog = await LoadCatalogAsync(volumeName, ct);
            if (!catalog.Files.Remove(fileId))
                throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");
            await SaveCatalogAsync(volumeName, catalog, ct);
        }
        finally
        {
            gate.Release();
        }

        // チャンクモード: S3 からチャンクを削除
        if (isChunkMode)
        {
            try { await _chunkStore.DeleteChunksAsync(volumeName, fileId, ct); }
            catch (Exception) { /* ベストエフォート */ }
        }

        // ファイル削除後に対応する SemaphoreSlim を破棄
        if (_fileGates.TryRemove(fileId, out var g))
            g.Dispose();
    }

    /// <summary>ボリューム削除時に対応する SemaphoreSlim を破棄。</summary>
    public void CleanupVolumeGates(string volumeName)
    {
        if (_volumeFileIds.TryRemove(volumeName, out var fileIds))
        {
            foreach (var fileId in fileIds)
            {
                if (_fileGates.TryRemove(fileId, out var gate))
                    gate.Dispose();
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

    /// <summary>ボリュームの使用量統計を返す。</summary>
    public async Task<E2eeVolumeStats> GetStatsAsync(string volumeName, string username, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);
        var catalog = await LoadCatalogAsync(volumeName, ct);
        var header = _volumeService.GetMounted(volumeName).Header;

        long totalUsed = catalog.Files.Values.Sum(f => Math.Max(0, f.EncryptedLength - 16L - (long)f.ChunkCount * 16));
        long userUsed = catalog.Files.Values
            .Where(f => f.OwnerUsername == username || string.IsNullOrEmpty(f.OwnerUsername))
            .Sum(f => Math.Max(0, f.EncryptedLength - 16L - (long)f.ChunkCount * 16));
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

/// <summary>部分読み取り用 Stream ラッパー。</summary>
file sealed class SubStream(Stream baseStream, long length) : Stream
{
    private readonly long _length = length;
    private long _remaining = length;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _length;
    public override long Position { get => _length - _remaining; set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_remaining <= 0) return 0;
        int toRead = (int)Math.Min(count, _remaining);
        int read = baseStream.Read(buffer, offset, toRead);
        _remaining -= read;
        return read;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) baseStream.Dispose();
        base.Dispose(disposing);
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
