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
    private static readonly TimeSpan LockLease = TimeSpan.FromMinutes(5);

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
        var key = FullPath(".locks/" + lockPath);
        while (true)
        {
            try
            {
                var expiry = DateTimeOffset.UtcNow.Add(LockLease).ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture);
                using var body = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(expiry));
                var response = await _client.PutObjectAsync(new PutObjectRequest
                {
                    BucketName = _bucket,
                    Key = key,
                    InputStream = body,
                    IfNoneMatch = "*",
                }, ct);
                return new S3LockReleaser(_client, _bucket, key, response.ETag);
            }
            catch (AmazonS3Exception ex) when (ex.StatusCode is System.Net.HttpStatusCode.PreconditionFailed or System.Net.HttpStatusCode.Conflict)
            {
                try
                {
                    var metadata = await _client.GetObjectMetadataAsync(_bucket, key, ct);
                    using var existing = await _client.GetObjectAsync(_bucket, key, ct);
                    using var reader = new StreamReader(existing.ResponseStream);
                    var text = await reader.ReadToEndAsync(ct);
                    if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var expiresAt) &&
                        expiresAt <= DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
                    {
                        await _client.DeleteObjectAsync(new DeleteObjectRequest
                        {
                            BucketName = _bucket,
                            Key = key,
                            IfMatch = metadata.ETag,
                        }, ct);
                        continue;
                    }
                }
                catch (AmazonS3Exception staleRace) when (staleRace.StatusCode is System.Net.HttpStatusCode.NotFound or System.Net.HttpStatusCode.PreconditionFailed or System.Net.HttpStatusCode.Conflict)
                {
                    continue;
                }
                await Task.Delay(100, ct);
            }
        }
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

    private sealed class S3LockReleaser : IDisposable
    {
        private readonly IAmazonS3 _client;
        private readonly string _bucket;
        private readonly string _key;
        private readonly SemaphoreSlim _gate = new(1, 1);
        private readonly Timer _renewal;
        private string? _etag;
        private int _released;

        public S3LockReleaser(IAmazonS3 client, string bucket, string key, string? etag)
        {
            _client = client;
            _bucket = bucket;
            _key = key;
            _etag = etag;
            _renewal = new Timer(_ => _ = RenewAsync(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
        }

        private async Task RenewAsync()
        {
            try
            {
                await _gate.WaitAsync();
                try
                {
                    if (Volatile.Read(ref _released) != 0) return;
                    var expiry = DateTimeOffset.UtcNow.Add(LockLease).ToUnixTimeMilliseconds()
                        .ToString(CultureInfo.InvariantCulture);
                    using var body = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(expiry));
                    var response = await _client.PutObjectAsync(new PutObjectRequest
                    {
                        BucketName = _bucket,
                        Key = _key,
                        InputStream = body,
                        IfMatch = _etag,
                    });
                    _etag = response.ETag;
                }
                finally
                {
                    _gate.Release();
                }
            }
            catch
            {
                // 一時障害は次の更新で再試行する。条件不一致なら所有権を失っているため
                // Dispose時の条件付き削除も失敗し、他所有者のロックは削除しない。
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) != 0) return;
            _renewal.Dispose();
            _gate.Wait();
            try
            {
                _client.DeleteObjectAsync(new DeleteObjectRequest
                {
                    BucketName = _bucket,
                    Key = _key,
                    IfMatch = _etag,
                }).GetAwaiter().GetResult();
            }
            catch (AmazonS3Exception ex) when (ex.StatusCode is System.Net.HttpStatusCode.NotFound or System.Net.HttpStatusCode.PreconditionFailed or System.Net.HttpStatusCode.Conflict) { }
            finally
            {
                _gate.Release();
                _gate.Dispose();
            }
        }
    }
}
