using System.Collections.Concurrent;
using Google.Cloud.Storage.V1;

namespace CistaNAS.Web.Storage;

/// <summary>
/// Google Cloud Storage プロバイダ。
/// メタデータを GCS バケットに保存し、volume.dat はローカルに保持。
/// Application Default Credentials (ADC) で認証。
/// </summary>
public sealed class GcsStorageProvider : IStorageProvider
{
    private readonly StorageClient _client;
    private readonly string _bucket;
    private readonly string _prefix;
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new(StringComparer.Ordinal);

    public GcsStorageProvider(string bucketName, string? pathPrefix)
    {
        _bucket = bucketName;
        _prefix = NormalizePrefix(pathPrefix);
        _client = StorageClient.Create();
    }

    private string FullPath(string blobPath) => _prefix + blobPath;

    private static string NormalizePrefix(string? prefix)
        => string.IsNullOrEmpty(prefix) ? "" : prefix.TrimEnd('/') + "/";

    private static bool IsGcsNotFound(Exception ex)
    {
        var prop = ex.GetType().GetProperty("HttpStatusCode");
        if (prop == null) return false;
        return prop.GetValue(ex) is System.Net.HttpStatusCode s && s == System.Net.HttpStatusCode.NotFound;
    }

    public async Task<byte[]?> ReadAsync(string blobPath, CancellationToken ct = default)
    {
        try
        {
            using var ms = new MemoryStream();
            await _client.DownloadObjectAsync(_bucket, FullPath(blobPath), ms,
                cancellationToken: ct);
            return ms.ToArray();
        }
        catch (Exception ex) when (IsGcsNotFound(ex))
        {
            return null;
        }
    }

    public async Task WriteAsync(string blobPath, Stream content, CancellationToken ct = default)
    {
        await _client.UploadObjectAsync(_bucket, FullPath(blobPath), null, content,
            cancellationToken: ct);
    }

    public Task WriteAtomicAsync(string blobPath, Stream content, CancellationToken ct = default)
        => WriteAsync(blobPath, content, ct);

    public async Task DeleteAsync(string blobPath, CancellationToken ct = default)
    {
        try { await _client.DeleteObjectAsync(_bucket, FullPath(blobPath), cancellationToken: ct); }
        catch (Exception) { }
    }

    public async Task<bool> ExistsAsync(string blobPath, CancellationToken ct = default)
    {
        try
        {
            await _client.GetObjectAsync(_bucket, FullPath(blobPath), cancellationToken: ct);
            return true;
        }
        catch (Exception ex) when (IsGcsNotFound(ex))
        {
            return false;
        }
    }

    public async Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default)
    {
        var result = new List<string>();
        string? blobPrefix = string.IsNullOrEmpty(prefix) ? null : FullPath(prefix);
        await foreach (var obj in _client.ListObjectsAsync(_bucket, blobPrefix))
        {
            string name = obj.Name;
            if (name.StartsWith(_prefix))
                name = name[_prefix.Length..];
            result.Add(name);
        }
        return result;
    }

    public Task<IDisposable> AcquireLockAsync(string lockPath, CancellationToken ct = default)
    {
        var semaphore = _locks.GetOrAdd(lockPath, _ => new SemaphoreSlim(1, 1));
        semaphore.Wait(ct);
        return Task.FromResult<IDisposable>(new LockReleaser(semaphore));
    }

    private sealed class LockReleaser(SemaphoreSlim semaphore) : IDisposable
    {
        public void Dispose() => semaphore.Release();
    }
}
