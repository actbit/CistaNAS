using CistaNAS.Web.Configuration;

namespace CistaNAS.Web.Storage;

/// <summary>
/// オブジェクトストレージ上の SQLite ファイルをダウンロード/アップロードする。
/// Provider が s3/azureblob/gcs の場合に使用。単一インスタンス前提。
/// ローカル DB は VolumeDataPath 配下に保存し、コンテナ再起動後も
/// 次回 DownloadAsync で復旧可能にする。
/// VolumeDataPath が未設定の場合はテンポラリファイルにフォールバック。
/// </summary>
public sealed class CloudSqliteSync : IDisposable
{
    private readonly IStorageProvider _storage;
    private readonly string _blobKey;
    private readonly string _localPath;
    private readonly bool _isTemp;
    private int _dirty; // 0 = clean, 1 = dirty（Interlocked 用）

    public CloudSqliteSync(IStorageProvider storage, StorageOptions storageOpts, DatabaseOptions dbOpts)
    {
        _storage = storage;
        _blobKey = dbOpts.BlobKey ?? "cista.db";

        // VolumeDataPath が設定されていれば永続パスに保存（ボリュームマウント対応）。
        // 未設定時はテンポラリファイルにフォールバック。
        var volDataPath = storageOpts.VolumeDataPath;
        if (!string.IsNullOrEmpty(volDataPath))
        {
            Directory.CreateDirectory(volDataPath);
            _localPath = Path.Combine(volDataPath, _blobKey);
            _isTemp = false;
        }
        else
        {
            _localPath = Path.GetTempFileName();
            _isTemp = true;
        }

        _dirty = 0;
    }

    public string LocalDbPath => _localPath;

    /// <summary>起動時にオブジェクトストレージから DB ファイルをダウンロードする。</summary>
    public async Task DownloadAsync(CancellationToken ct = default)
    {
        byte[]? data = await _storage.ReadAsync(_blobKey, ct);
        if (data is not null)
            await File.WriteAllBytesAsync(_localPath, data, ct);
        else
            await File.WriteAllBytesAsync(_localPath, [], ct);
    }

    /// <summary>変更をマークする。</summary>
    public void MarkDirty() => Interlocked.Exchange(ref _dirty, 1);

    /// <summary>変更があればオブジェクトストレージにアップロードする。</summary>
    public async Task UploadIfDirtyAsync(CancellationToken ct = default)
    {
        if (Interlocked.CompareExchange(ref _dirty, 0, 1) == 0) return;
        await using var fs = File.OpenRead(_localPath);
        await _storage.WriteAtomicAsync(_blobKey, fs, ct);
    }

    public void Dispose()
    {
        // テンポラリパスのみ削除。VolumeDataPath 配下のファイルは永続データとして保持。
        if (_isTemp)
            try { File.Delete(_localPath); } catch (IOException) { }
    }
}
