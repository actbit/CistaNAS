using System.Collections.Concurrent;
using System.Threading;
using Amazon.S3;
using Amazon.S3.Model;
using System.Globalization;

namespace CistaNAS.Web.Storage;

/// <summary>
/// AWS S3 互換ストレージプロバイダ（MinIO / LocalStack 対応）。
/// メタデータを S3 バケットに保存し、volume.dat はローカルに保持。
/// </summary>
public sealed class S3StorageProvider : IStorageProvider, IAsyncDisposable
{
    private readonly IAmazonS3 _client;
    private readonly string _bucket;
    private readonly string _prefix;
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new(StringComparer.Ordinal);

    public S3StorageProvider(string bucket, string region, string? endpointOverride, string? pathPrefix)
    {
        _bucket = bucket;
        _prefix = NormalizePrefix(pathPrefix);

        var config = new AmazonS3Config
        {
            RegionEndpoint = string.IsNullOrEmpty(region)
                ? Amazon.RegionEndpoint.USEast1
                : Amazon.RegionEndpoint.GetBySystemName(region),
            ForcePathStyle = !string.IsNullOrEmpty(endpointOverride),
        };
        if (!string.IsNullOrEmpty(endpointOverride))
            config.ServiceURL = endpointOverride;

        _client = new AmazonS3Client(config);
    }

    private string FullPath(string blobPath) => _prefix + blobPath;

    private static string NormalizePrefix(string? prefix)
        => string.IsNullOrEmpty(prefix) ? "" : prefix.TrimEnd('/') + "/";

    public async Task<byte[]?> ReadAsync(string blobPath, CancellationToken ct = default)
    {
        try
        {
            using var response = await _client.GetObjectAsync(_bucket, FullPath(blobPath), ct);
            using var ms = new MemoryStream();
            await response.ResponseStream.CopyToAsync(ms, ct);
            return ms.ToArray();
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }
    }

    public async Task WriteAsync(string blobPath, Stream content, CancellationToken ct = default)
    {
        // 呼び出し側が正しい Position を設定済みの前提。
        // 上位の VolumeMetadataStore.SaveAsync は MemoryStream を渡すため不要だが、
        // 将来の呼び出し元での誤用を防ぐため検査を残す。
        if (content.CanSeek && content.Position != 0 && content.Length > 0)
            content.Position = 0;
        var request = new PutObjectRequest
        {
            BucketName = _bucket,
            Key = FullPath(blobPath),
            InputStream = content,
        };
        await _client.PutObjectAsync(request, ct);
    }

    public async Task WriteAtomicAsync(string blobPath, Stream content, CancellationToken ct = default)
    {
        // 単一の上書き PUT で原子的に置換。S3 の単一オブジェクト PUT は
        // read-after-write 強一貫性で原子的（旧値か新値かの二者択一、部分破損しない）。
        // tmp→copy→delete 連鎖と異なり故障点が1つで、孤立 tmp オブジェクトも発生しない。
        if (content.CanSeek && content.Position != 0)
            content.Position = 0;
        var request = new PutObjectRequest
        {
            BucketName = _bucket,
            Key = FullPath(blobPath),
            InputStream = content,
        };
        await _client.PutObjectAsync(request, ct);
    }

    public async Task DeleteAsync(string blobPath, CancellationToken ct = default)
    {
        try { await _client.DeleteObjectAsync(_bucket, FullPath(blobPath), ct); }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound) { }
    }

    public async Task<bool> ExistsAsync(string blobPath, CancellationToken ct = default)
    {
        try
        {
            await _client.GetObjectMetadataAsync(_bucket, FullPath(blobPath), ct);
            return true;
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return false;
        }
    }

    public async Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default)
    {
        var request = new ListObjectsV2Request
        {
            BucketName = _bucket,
            Prefix = string.IsNullOrEmpty(prefix) ? null : FullPath(prefix),
        };

        var result = new List<string>();
        ListObjectsV2Response response;
        do
        {
            response = await _client.ListObjectsV2Async(request, ct);
            foreach (var obj in response.S3Objects)
            {
                string key = obj.Key;
                if (key.StartsWith(_prefix))
                    key = key[_prefix.Length..];
                result.Add(key);
            }
            request.ContinuationToken = response.NextContinuationToken;
        } while (response.IsTruncated == true);

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
        // 保持中に TryRemove すると次の AcquireLockAsync が新しいセマフォを作成し、
        // 古い保持者の Release が新しいセマフォに伝わらずデッドロックするため削除しない。
    }

    public ValueTask DisposeAsync()
    {
        _client.Dispose();
        return default;
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
