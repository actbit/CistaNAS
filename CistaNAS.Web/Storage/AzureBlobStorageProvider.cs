using System.Threading;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;

namespace CistaNAS.Web.Storage;

/// <summary>
/// Azure Blob Storage プロバイダ。
/// メタデータを Blob コンテナに保存し、volume.dat はローカルに保持。
/// </summary>
public sealed class AzureBlobStorageProvider : IStorageProvider
{
    private readonly BlobContainerClient _container;
    private readonly string _prefix;
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
        // 単一の上書きアップロードで原子的に置換（Azure Blob の Upload は原子的）。
        // tmp→copy→delete 連鎖を廃止し、故障点と孤立 Blob を削減。
        var finalClient = _container.GetBlobClient(FullPath(blobPath));
        await finalClient.UploadAsync(content, overwrite: true, ct);
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
        var blob = _container.GetBlobClient(FullPath(".locks/" + lockPath));
        try { await blob.UploadAsync(BinaryData.FromString("lock"), overwrite: false, ct); }
        catch (RequestFailedException ex) when (ex.Status == 409) { }
        var lease = blob.GetBlobLeaseClient();
        while (true)
        {
            try
            {
                await lease.AcquireAsync(TimeSpan.FromSeconds(60), conditions: null, cancellationToken: ct);
                return new BlobLeaseReleaser(lease);
            }
            catch (RequestFailedException ex) when (ex.Status == 409)
            {
                await Task.Delay(100, ct);
            }
        }
    }

    /// <summary>ロックを辞書から解除。保持中のセマフォ削除によるデッドロックを防ぐため no-op。</summary>
    public void RemoveLock(string lockPath)
    {
        // セマフォはプロセス存続期間中辞書に残る。
    }

    private sealed class BlobLeaseReleaser(BlobLeaseClient lease) : IDisposable
    {
        private readonly Timer _renewal = new(async _ =>
        {
            try { await lease.RenewAsync(); }
            catch { /* 一時障害は次回更新で再試行する。Timerコールバックから例外を漏らさない。 */ }
        }, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        private int _released;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) != 0) return;
            _renewal.Dispose();
            try { lease.Release(); } catch (RequestFailedException) { }
        }
    }
}
