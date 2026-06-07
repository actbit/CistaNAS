using System.Collections.Concurrent;
using System.Threading;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

namespace CistaNAS.Web.Storage;

/// <summary>
/// Azure Blob Storage プロバイダ。
/// メタデータを Blob コンテナに保存し、volume.dat はローカルに保持。
/// </summary>
public sealed class AzureBlobStorageProvider : IStorageProvider
{
    private readonly BlobContainerClient _container;
    private readonly string _prefix;
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new(StringComparer.Ordinal);

    /// <summary>コンテナの初期化タスク（遅延実行）。</summary>
    private readonly Task _init;

    public AzureBlobStorageProvider(string connectionString, string containerName, string? pathPrefix)
    {
        _prefix = NormalizePrefix(pathPrefix);
        _container = new BlobContainerClient(connectionString, containerName);
        _init = _container.CreateIfNotExistsAsync();
    }

    private string FullPath(string blobPath) => _prefix + blobPath;

    private static string NormalizePrefix(string? prefix)
        => string.IsNullOrEmpty(prefix) ? "" : prefix.TrimEnd('/') + "/";

    public async Task<byte[]?> ReadAsync(string blobPath, CancellationToken ct = default)
    {
        await _init;
        try
        {
            var client = _container.GetBlobClient(FullPath(blobPath));
            using var ms = new MemoryStream();
            await client.DownloadToAsync(ms, ct);
            return ms.ToArray();
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    public async Task WriteAsync(string blobPath, Stream content, CancellationToken ct = default)
    {
        await _init;
        var client = _container.GetBlobClient(FullPath(blobPath));
        await client.UploadAsync(content, overwrite: true, ct);
    }

    public async Task WriteAtomicAsync(string blobPath, Stream content, CancellationToken ct = default)
    {
        await _init;
        string tempPath = FullPath(blobPath) + ".tmp";
        var tempClient = _container.GetBlobClient(tempPath);
        await tempClient.UploadAsync(content, overwrite: true, ct);
        var finalClient = _container.GetBlobClient(FullPath(blobPath));
        await finalClient.SyncCopyFromUriAsync(tempClient.Uri, cancellationToken: ct);
        try { await tempClient.DeleteAsync(cancellationToken: ct); }
        catch (RequestFailedException) { /* ベストエフォート */ }
    }

    public async Task DeleteAsync(string blobPath, CancellationToken ct = default)
    {
        await _init;
        try
        {
            var client = _container.GetBlobClient(FullPath(blobPath));
            await client.DeleteAsync(cancellationToken: ct);
        }
        catch (RequestFailedException ex) when (ex.Status == 404) { }
    }

    public async Task<bool> ExistsAsync(string blobPath, CancellationToken ct = default)
    {
        await _init;
        var client = _container.GetBlobClient(FullPath(blobPath));
        return await client.ExistsAsync(ct);
    }

    public async Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default)
    {
        await _init;
        var result = new List<string>();
        string blobPrefix = string.IsNullOrEmpty(prefix) ? _prefix : FullPath(prefix);
        await foreach (var blob in _container.GetBlobsAsync(
            traits: BlobTraits.None, states: BlobStates.None,
            prefix: blobPrefix, cancellationToken: ct))
        {
            string name = blob.Name;
            if (name.StartsWith(_prefix))
                name = name[_prefix.Length..];
            result.Add(name);
        }
        return result;
    }

    public async Task<IDisposable> AcquireLockAsync(string lockPath, CancellationToken ct = default)
    {
        await _init;
        var semaphore = _locks.GetOrAdd(lockPath, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync(ct);
        return new LockReleaser(semaphore);
    }

    /// <summary>ロックを辞書から解除。保持中のセマフォ削除によるデッドロックを防ぐため no-op。</summary>
    public void RemoveLock(string lockPath)
    {
        // セマフォはプロセス存続期間中辞書に残る。
    }

    private sealed class LockReleaser(SemaphoreSlim semaphore) : IDisposable
    {
        private int _released;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
                semaphore.Release();
        }
    }
}
