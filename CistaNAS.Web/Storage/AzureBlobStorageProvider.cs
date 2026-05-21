using System.Collections.Concurrent;
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

    public AzureBlobStorageProvider(string connectionString, string containerName, string? pathPrefix)
    {
        _prefix = NormalizePrefix(pathPrefix);
        _container = new BlobContainerClient(connectionString, containerName);
        _container.CreateIfNotExists();
    }

    private string FullPath(string blobPath) => _prefix + blobPath;

    private static string NormalizePrefix(string? prefix)
        => string.IsNullOrEmpty(prefix) ? "" : prefix.TrimEnd('/') + "/";

    public async Task<byte[]?> ReadAsync(string blobPath, CancellationToken ct = default)
    {
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
        var client = _container.GetBlobClient(FullPath(blobPath));
        await client.UploadAsync(content, overwrite: true, ct);
    }

    public Task WriteAtomicAsync(string blobPath, Stream content, CancellationToken ct = default)
        => WriteAsync(blobPath, content, ct);

    public async Task DeleteAsync(string blobPath, CancellationToken ct = default)
    {
        try
        {
            var client = _container.GetBlobClient(FullPath(blobPath));
            await client.DeleteAsync(cancellationToken: ct);
        }
        catch (RequestFailedException) { }
    }

    public async Task<bool> ExistsAsync(string blobPath, CancellationToken ct = default)
    {
        var client = _container.GetBlobClient(FullPath(blobPath));
        return await client.ExistsAsync(ct);
    }

    public async Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default)
    {
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
        var semaphore = _locks.GetOrAdd(lockPath, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync(ct);
        return new LockReleaser(semaphore);
    }

    private sealed class LockReleaser(SemaphoreSlim semaphore) : IDisposable
    {
        public void Dispose() => semaphore.Release();
    }
}
