using CistaNAS.Web.Configuration;
using Microsoft.Extensions.Hosting;

namespace CistaNAS.Web.Storage;

/// <summary>
/// オブジェクトストレージ上の SQLite ファイルをダウンロード/アップロードする。
/// Provider が s3/azureblob/gcs の場合に使用。単一インスタンス前提。
/// ローカル DB は VolumeDataPath 配下に保存し、コンテナ再起動後も
/// 次回 DownloadAsync で復旧可能にする。
/// VolumeDataPath が未設定の場合はテンポラリファイルにフォールバック。
/// IHostedService を実装し、シャットダウン時に非同期でアップロードする。
/// </summary>
public sealed class CloudSqliteSync : IHostedService, IDisposable
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
            // テンポラリでも固定パス（プロセス再起動で同じファイルを再利用）。
            // シャットダウン時のアップロード失敗から次回起動で復旧できるよう、
            // 毎回新しい空ファイルを作らずパスごとのファイルを維持する。
            _localPath = Path.Combine(Path.GetTempPath(), _blobKey);
            _isTemp = true;
        }

        _dirty = 0;
    }

    public string LocalDbPath => _localPath;

    /// <summary>起動時にオブジェクトストレージから DB ファイルをダウンロードする。</summary>
    /// <remarks>
    /// ローカルが既に存在する場合は上書きしない（ローカルを真実のソースとする）。
    /// シャットダウン時のアップロード失敗でクラウドが古いままでも、次回起動で
    /// ローカルの最新状態を維持し、DB 変更の消失を防ぐ。
    /// </remarks>
    public async Task DownloadAsync(CancellationToken ct = default)
    {
        if (File.Exists(_localPath)) return;

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

    private int _disposed;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        // テンポラリパスのみ削除。VolumeDataPath 配下のファイルは永続データとして保持。
        if (_isTemp)
            try { File.Delete(_localPath); } catch (IOException) { }
    }

    public Task StartAsync(CancellationToken ct) => Task.CompletedTask;

    public async Task StopAsync(CancellationToken ct)
    {
        // シャットダウン時の DB アップロードを確実化（リトライ付き）。
        // 失敗してもローカルファイルは保持し、次回起動の DownloadAsync で
        // ローカルが優先されることで DB 変更の消失を防ぐ。
        Exception? lastError = null;
        for (int attempt = 0; attempt < 3 && !ct.IsCancellationRequested; attempt++)
        {
            try
            {
                await UploadIfDirtyAsync(ct);
                lastError = null;
                break;
            }
            catch (Exception ex)
            {
                lastError = ex;
                if (attempt < 2)
                {
                    try { await Task.Delay(TimeSpan.FromSeconds(2 * (attempt + 1)), ct); }
                    catch (OperationCanceledException) { break; }
                }
            }
        }

        if (lastError is not null)
            Console.Error.WriteLine($"[Error] Cloud sync upload failed during shutdown: {lastError.Message}");

        // アップロード成功時のみテンポラリファイルを削除（クラウドが最新のため）。
        // 永続ファイルは Dispose で削除されない。失敗時はテンポラリも保持し次回起動で復旧。
        if (_isTemp && lastError is null)
            Dispose();
    }
}
