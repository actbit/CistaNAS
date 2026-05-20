using System.Collections.Concurrent;
using System.Text.Json;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// E2EE ボリュームのファイル管理。opaque blob として volume.dat に格納し、
/// catalog-e2ee.json に FileId ベースのメタデータを保持する。
/// </summary>
public sealed class E2eeFileService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly VolumeService _volumeService;
    private readonly string _dataRoot;
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _fileGates = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _volumeGates = new(StringComparer.Ordinal);

    public E2eeFileService(VolumeService volumeService, IOptions<CistaNasOptions> options)
    {
        _volumeService = volumeService;
        _dataRoot = options.Value.DataRoot;
    }

    /// <summary>E2EE ボリュームのヘッダを取得。E2EE でなければ例外。</summary>
    private VolumeHeader GetE2eeHeader(string volumeName)
    {
        var (_, header) = _volumeService.GetMounted(volumeName);
        if (!header.IsE2ee)
            throw new FileServiceException($"ボリューム '{volumeName}' は E2EE ボリュームではありません。");
        return header;
    }

    /// <summary>ファイルエントリを作成し、FileId を返す。</summary>
    public E2eeFileEntry CreateFile(string volumeName, E2eeCreateFileRequest request)
    {
        var header = GetE2eeHeader(volumeName);

        var volGate = _volumeGates.GetOrAdd(volumeName, _ => new SemaphoreSlim(1, 1));
        volGate.Wait();
        try
        {
            var catalog = LoadCatalog(volumeName);

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
            };

            catalog.Files[fileId] = entry;
            SaveCatalog(volumeName, catalog);

            // ファイル gate も登録（UploadChunkAsync で使用）
            _fileGates.TryAdd(fileId, new SemaphoreSlim(1, 1));
            return entry;
        }
        finally
        {
            volGate.Release();
        }
    }

    /// <summary>チャンクをアップロードして volume.dat に書き込む。</summary>
    public async Task UploadChunkAsync(string volumeName, string fileId, int chunkIndex, Stream data, long dataLength, CancellationToken ct = default)
    {
        GetE2eeHeader(volumeName);

        var gate = _fileGates.GetOrAdd(fileId, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            var catalog = LoadCatalog(volumeName);

            if (!catalog.Files.TryGetValue(fileId, out var entry))
                throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");

            // チャンクはシーケンシャルに書き込む — 前のチャンクまでの累積サイズがオフセット
            long chunkOffset = entry.Offset + entry.ChunkSizes.Sum(s => (long)s);

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
                fs.Write(buffer, 0, read);
                written += read;
                remaining -= read;
            }
            fs.Flush();

            // チャンクサイズを記録
            while (entry.ChunkSizes.Count <= chunkIndex)
                entry.ChunkSizes.Add(0);
            entry.ChunkSizes[chunkIndex] = (int)written;
            SaveCatalog(volumeName, catalog);
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>チャンクをダウンロード。</summary>
    public (Stream Stream, long Length) DownloadChunk(string volumeName, string fileId, int chunkIndex)
    {
        GetE2eeHeader(volumeName);
        var catalog = LoadCatalog(volumeName);

        if (!catalog.Files.TryGetValue(fileId, out var entry))
            throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");

        if (chunkIndex < 0 || chunkIndex >= entry.ChunkCount)
            throw new FileServiceException($"チャンクインデックス {chunkIndex} は範囲外です。");

        long chunkOffset = entry.Offset;
        for (int i = 0; i < chunkIndex; i++)
            chunkOffset += entry.ChunkSizes[i];

        long chunkLength = chunkIndex < entry.ChunkSizes.Count
            ? entry.ChunkSizes[chunkIndex]
            : 0;

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
    public void FinalizeFile(string volumeName, string fileId, E2eeFinalizeFileRequest request)
    {
        GetE2eeHeader(volumeName);
        var catalog = LoadCatalog(volumeName);

        if (!catalog.Files.TryGetValue(fileId, out var entry))
            throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");

        entry.EncryptedLength = request.ActualEncryptedLength;
        entry.ModifiedAt = DateTimeOffset.UtcNow;
        SaveCatalog(volumeName, catalog);

        // ゲートは残しておき、Cleanup に任せる（進行中の UploadChunkAsync を保護）
    }

    /// <summary>ファイル一覧を返す。</summary>
    public E2eeListFilesResponse ListFiles(string volumeName)
    {
        GetE2eeHeader(volumeName);
        var catalog = LoadCatalog(volumeName);

        // カタログに存在しないファイルIDのゲートを掃除
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
    public void DeleteFile(string volumeName, string fileId)
    {
        GetE2eeHeader(volumeName);
        var catalog = LoadCatalog(volumeName);

        if (!catalog.Files.Remove(fileId))
            throw new FileServiceException($"ファイル '{fileId}' が見つかりません。");

        SaveCatalog(volumeName, catalog);
    }

    /// <summary>E2EE マウント情報を返す。</summary>
    public E2eeMountResponse GetMountInfo(string volumeName)
    {
        var header = GetE2eeHeader(volumeName);
        return new E2eeMountResponse(header.ChunkSize, header.EncryptionMode);
    }

    // ---- 内部ヘルパー ----

    private E2eeCatalog LoadCatalog(string volumeName)
    {
        string path = GetCatalogPath(volumeName);
        if (!File.Exists(path)) return new E2eeCatalog();
        using var fs = File.OpenRead(path);
        return JsonSerializer.Deserialize<E2eeCatalog>(fs, JsonOptions) ?? new E2eeCatalog();
    }

    private void SaveCatalog(string volumeName, E2eeCatalog catalog)
    {
        string path = GetCatalogPath(volumeName);
        string tmp = path + ".tmp";
        using (var fs = File.Create(tmp))
            JsonSerializer.Serialize(fs, catalog, JsonOptions);
        File.Move(tmp, path, overwrite: true);
    }

    private string GetCatalogPath(string volumeName)
        => Path.Combine(_dataRoot, volumeName, "catalog-e2ee.json");

    private string GetDataPath(string volumeName)
        => Path.Combine(_dataRoot, volumeName, "volume.dat");
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
