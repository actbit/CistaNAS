using System.Collections.Concurrent;
using System.Threading;
using Google;
using Google.Cloud.Storage.V1;

namespace CistaNAS.Web.Storage;

/// <summary>
/// Google Cloud Storage プロバイダ。
/// メタデータを GCS バケットに保存し、volume.dat はローカルに保持。
/// Application Default Credentials (ADC) で認証。
/// </summary>
public sealed class GcsStorageProvider : IStorageProvider, IAsyncDisposable
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
        return ex is GoogleApiException gae && gae.HttpStatusCode == System.Net.HttpStatusCode.NotFound;
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

    public async Task WriteAtomicAsync(string blobPath, Stream content, CancellationToken ct = default)
    {
        // GUID を付与して同時実行時の衝突を防止（S3/Azure 実装との整合性）
        string tempPath = FullPath(blobPath) + ".tmp-" + Guid.NewGuid().ToString("N");
        await _client.UploadObjectAsync(_bucket, tempPath, null, content, cancellationToken: ct);
        // CopyObjectAsync は内部で Rewrite API を使用し、コピー完了までポーリングする。
        await _client.CopyObjectAsync(_bucket, tempPath, _bucket, FullPath(blobPath),
            cancellationToken: ct);
        try { await _client.DeleteObjectAsync(_bucket, tempPath, cancellationToken: ct); }
        catch (GoogleApiException) { /* ベストエフォート */ }
    }

    public async Task DeleteAsync(string blobPath, CancellationToken ct = default)
    {
        try { await _client.DeleteObjectAsync(_bucket, FullPath(blobPath), cancellationToken: ct); }
        catch (Exception ex) when (IsGcsNotFound(ex)) { }
    }

    public async Task<bool> ExistsAsync(string blobPath, CancellationToken ct = default)
    {
        try
        {
            var obj = await _client.GetObjectAsync(_bucket, FullPath(blobPath), cancellationToken: ct);
            // GetObjectAsync はメタデータのみを取得（コンテンツはダウンロードしない）
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

    public async Task<IDisposable> AcquireLockAsync(string lockPath, CancellationToken ct = default)
    {
        var semaphore = _locks.GetOrAdd(lockPath, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync(ct);
        return new LockReleaser(semaphore);
    }

    /// <summary>ロックを辞書から解除。保持中のセマフォ削除によるデッドロックを防ぐため no-op。</summary>
    public void RemoveLock(string lockPath)
    {
        // セマフォはプロセス存続期間中辞書に残る。
    }

    public async ValueTask DisposeAsync()
    {
        _client.Dispose();
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
