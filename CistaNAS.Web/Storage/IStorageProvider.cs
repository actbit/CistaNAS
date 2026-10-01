namespace CistaNAS.Web.Storage;

/// <summary>
/// メタデータ保存先の抽象インターフェース。
/// 実装: LocalStorageProvider, S3StorageProvider, AzureBlobStorageProvider, GcsStorageProvider
/// </summary>
public interface IStorageProvider
{
    /// <summary>保存先を特定する安定した識別子。資格情報を含めず、鍵更新でも変わらない。</summary>
    string RecoveryIdentity => throw new NotSupportedException("This provider must identify its SQLite recovery destination.");

    Task<byte[]?> ReadAsync(string blobPath, CancellationToken ct = default);
    Task WriteAsync(string blobPath, Stream content, CancellationToken ct = default);
    Task WriteAtomicAsync(string blobPath, Stream content, CancellationToken ct = default);
    Task DeleteAsync(string blobPath, CancellationToken ct = default);
    Task<bool> ExistsAsync(string blobPath, CancellationToken ct = default);
    Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default);
    Task<IDisposable> AcquireLockAsync(string lockPath, CancellationToken ct = default);
    void RemoveLock(string lockPath);
}
