using CistaNAS.Web.Configuration;
using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;

namespace CistaNAS.Web.Storage;

/// <summary>
/// オブジェクトストレージ上の SQLite ファイルをダウンロード/アップロードする。
/// Provider が s3/azureblob/gcs の場合に使用。単一インスタンス前提。
/// ローカル DB は VolumeDataPath 配下に保存し、コンテナ再起動後も
/// 次回 DownloadAsync で復旧可能にする。
/// VolumeDataPath が未設定の場合はテンポラリファイルにフォールバック。
/// SQLite backup API で WAL を含む整合したスナップショットを定期同期する。
/// ローカル DB は同期成否にかかわらず復旧元として保持する。
/// </summary>
public sealed class CloudSqliteSync : BackgroundService
{
    private readonly IStorageProvider _storage;
    private readonly string _blobKey;
    private readonly string _localPath;
    private readonly SemaphoreSlim _syncGate = new(1, 1);
    private readonly TimeSpan _interval;
    private readonly ILogger<CloudSqliteSync> _logger;
    private int _dirty; // 0 = clean, 1 = dirty（Interlocked 用）

    public CloudSqliteSync(IStorageProvider storage, StorageOptions storageOpts, DatabaseOptions dbOpts,
        ILogger<CloudSqliteSync>? logger = null)
    {
        _storage = storage;
        _blobKey = dbOpts.BlobKey ?? "cista.db";
        _interval = TimeSpan.FromSeconds(Math.Max(1, dbOpts.SyncIntervalSeconds));
        _logger = logger ?? NullLogger<CloudSqliteSync>.Instance;

        // 同じ DB オブジェクト名でも保存先が異なれば復旧元を共有しない。
        // BlobKey はクラウドの名前であり、ローカルファイルパスとして解釈しない。
        string root = Path.GetFullPath(string.IsNullOrEmpty(storageOpts.VolumeDataPath)
            ? Path.GetTempPath() : storageOpts.VolumeDataPath);
        string scope = JsonSerializer.Serialize(new[] { storage.RecoveryIdentity, _blobKey });
        string identifier = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(scope))).ToLowerInvariant();
        _localPath = Path.Combine(root, ".cistanas-sqlite", identifier, "database.sqlite");
        string? legacy = GetLegacyPath(root, _blobKey);
        if (!File.Exists(_localPath) && legacy is not null &&
            (File.Exists(legacy) || File.Exists(legacy + "-wal") || File.Exists(legacy + "-shm")))
            throw new InvalidOperationException($"Unbound SQLite recovery database found at '{legacy}'. " +
                "Stop the server and confirm that it belongs to this storage destination before moving the DB, WAL and SHM " +
                $"to '{_localPath}' and its matching sidecar names. The original files have been retained.");
        Directory.CreateDirectory(Path.GetDirectoryName(_localPath)!);
        // Dirty のメモリ状態は再起動で失われる。既存のローカル DB は必ず再送する。
        _dirty = File.Exists(_localPath) ? 1 : 0;
    }

    public string LocalDbPath => _localPath;

    internal static string? GetLegacyPath(string root, string key)
    {
        try
        {
            if (Path.IsPathRooted(key)) return null;
            string full = Path.GetFullPath(Path.Combine(root, key));
            string boundary = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
            return full.StartsWith(boundary, OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) ? full : null;
        }
        catch (ArgumentException) { return null; }
        catch (NotSupportedException) { return null; }
    }

    /// <summary>起動時にオブジェクトストレージから DB ファイルをダウンロードする。</summary>
    /// <remarks>
    /// ローカルが既に存在する場合は上書きしない（ローカルを真実のソースとする）。
    /// シャットダウン時のアップロード失敗でクラウドが古いままでも、次回起動で
    /// ローカルの最新状態を維持し、DB 変更の消失を防ぐ。
    /// </remarks>
    public async Task DownloadAsync(CancellationToken ct = default)
    {
        await _syncGate.WaitAsync(ct);
        try
        {
            if (!File.Exists(_localPath))
            {
                byte[]? data = await _storage.ReadAsync(_blobKey, ct);
                string temporary = _localPath + ".download-" + Guid.NewGuid().ToString("N");
                try
                {
                    await using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        await file.WriteAsync(data ?? [], ct);
                        await file.FlushAsync(ct);
                        file.Flush(flushToDisk: true);
                    }
                    ct.ThrowIfCancellationRequested();
                    File.Move(temporary, _localPath);
                }
                finally { File.Delete(temporary); }
            }
            // マイグレーションによる変更も最初の同期に含める。
            MarkDirty();
        }
        finally { _syncGate.Release(); }
    }

    /// <summary>変更をマークする。</summary>
    public void MarkDirty() => Interlocked.Exchange(ref _dirty, 1);

    /// <summary>変更があればオブジェクトストレージにアップロードする。</summary>
    public async Task UploadIfDirtyAsync(CancellationToken ct = default)
    {
        await _syncGate.WaitAsync(ct);
        string? snapshot = null;
        try
        {
            // 処理中の MarkDirty は次回の同期対象として残る。
            if (Interlocked.Exchange(ref _dirty, 0) == 0) return;
            try
            {
                snapshot = _localPath + ".snapshot-" + Guid.NewGuid().ToString("N");
                // DB ファイルを直接コピーすると WAL のコミットを落とし、書き込み中の
                // ページを混在させる。backup API は整合した単一 DB を生成する。
                await Task.Run(() => CreateSnapshot(snapshot, ct), ct);
                await using var fs = File.OpenRead(snapshot);
                await _storage.WriteAtomicAsync(_blobKey, fs, ct);
            }
            catch
            {
                Interlocked.Exchange(ref _dirty, 1);
                throw;
            }
        }
        finally
        {
            try { if (snapshot is not null) File.Delete(snapshot); }
            finally { _syncGate.Release(); }
        }
    }

    private void CreateSnapshot(string snapshot, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var source = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _localPath, Mode = SqliteOpenMode.ReadWrite, Pooling = false,
        }.ToString());
        using var destination = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = snapshot, Pooling = false,
        }.ToString());
        source.Open();
        destination.Open();
        source.BackupDatabase(destination);
        ct.ThrowIfCancellationRequested();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await UploadIfDirtyAsync(stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) { _logger.LogError(ex, "SQLite のクラウド同期に失敗しました。ローカル DB を保持し、再試行します。"); }
            try { await Task.Delay(_interval, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }

    public override async Task StopAsync(CancellationToken ct)
    {
        await base.StopAsync(ct);
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
            _logger.LogError(lastError, "シャットダウン時の SQLite 同期に失敗しました。次回起動でローカル DB を再送します。");
        // Dispose / キャンセル後もローカル DB と WAL を削除しない。
    }
}

/// <summary>明示的トランザクションは SaveChanges 後に確定するため、コミット時も再送対象にする。</summary>
public sealed class CloudSqliteTransactionInterceptor(CloudSqliteSync sync) : DbTransactionInterceptor
{
    public override void TransactionCommitted(DbTransaction transaction, TransactionEndEventData eventData)
        => sync.MarkDirty();

    public override Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData eventData,
        CancellationToken cancellationToken = default)
    {
        sync.MarkDirty();
        return Task.CompletedTask;
    }
}

/// <summary>EF のコミット成功後にクラウド SQLite 同期を dirty にする。</summary>
public sealed class CloudSqliteSaveChangesInterceptor(CloudSqliteSync sync) : SaveChangesInterceptor
{
    public override int SavedChanges(SaveChangesCompletedEventData eventData, int result)
    {
        sync.MarkDirty();
        return base.SavedChanges(eventData, result);
    }

    public override ValueTask<int> SavedChangesAsync(
        SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
    {
        sync.MarkDirty();
        return base.SavedChangesAsync(eventData, result, cancellationToken);
    }
}
