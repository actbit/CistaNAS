namespace CistaNAS.Web.Storage;

/// <summary>
/// メタデータ保存先の抽象インターフェース。
/// 実装: LocalStorageProvider, S3StorageProvider, AzureBlobStorageProvider, GcsStorageProvider
/// </summary>
public interface IStorageProvider
{
    Task<byte[]?> ReadAsync(string blobPath, CancellationToken ct = default);
    Task WriteAsync(string blobPath, Stream content, CancellationToken ct = default);
    Task WriteAtomicAsync(string blobPath, Stream content, CancellationToken ct = default);
    Task DeleteAsync(string blobPath, CancellationToken ct = default);
    Task<bool> ExistsAsync(string blobPath, CancellationToken ct = default);
    Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default);
    Task<IDisposable> AcquireLockAsync(string lockPath, CancellationToken ct = default);
}
