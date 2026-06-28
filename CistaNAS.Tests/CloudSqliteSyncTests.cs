using CistaNAS.Web.Configuration;
using CistaNAS.Web.Storage;

namespace CistaNAS.Tests;

/// <summary>
/// CloudSqliteSync のシャットダウン時データ消失防止のテスト。
/// クラウド構成で SQLite DB の変更がシャットダウン失敗や次回起動の上書きで
/// 消失しないことを検証する。
/// </summary>
public class CloudSqliteSyncTests
{
    /// <summary>全操作が失敗するストレージ（シャットダウンアップロード失敗をシミュレート）。</summary>
    private sealed class FaultyStorageProvider : IStorageProvider
    {
        public Task<byte[]?> ReadAsync(string blobPath, CancellationToken ct = default)
            => Task.FromResult<byte[]?>(null);
        public Task WriteAsync(string blobPath, Stream content, CancellationToken ct = default)
            => throw new IOException("simulated failure");
        public Task WriteAtomicAsync(string blobPath, Stream content, CancellationToken ct = default)
            => throw new IOException("simulated failure");
        public Task DeleteAsync(string blobPath, CancellationToken ct = default) => Task.CompletedTask;
        public Task<bool> ExistsAsync(string blobPath, CancellationToken ct = default) => Task.FromResult(false);
        public Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());
        public Task<IDisposable> AcquireLockAsync(string lockPath, CancellationToken ct = default)
            => Task.FromResult<IDisposable>(new NoopDisposable());
        public void RemoveLock(string lockPath) { }
        private sealed class NoopDisposable : IDisposable
        {
            public void Dispose() { }
        }
    }

    private static string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cista-cloudsync-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public async Task DownloadAsync_LocalExists_DoesNotOverwrite()
    {
        var localDir = NewTempDir();
        var cloudDir = NewTempDir();
        try
        {
            // ローカルに「最新」、クラウドに「古い」データ
            string localPath = Path.Combine(localDir, "test.db");
            await File.WriteAllBytesAsync(localPath, "LOCAL-LATEST"u8.ToArray());
            var storage = new LocalStorageProvider(cloudDir);
            await storage.WriteAsync("test.db", new MemoryStream("CLOUD-STALE"u8.ToArray()));

            var sync = new CloudSqliteSync(storage,
                new StorageOptions { VolumeDataPath = localDir },
                new DatabaseOptions { BlobKey = "test.db" });

            await sync.DownloadAsync();

            // ローカルは上書きされず「最新」のまま
            var localContent = await File.ReadAllBytesAsync(localPath);
            Assert.Equal("LOCAL-LATEST"u8.ToArray(), localContent);
        }
        finally
        {
            try { Directory.Delete(localDir, true); } catch { }
            try { Directory.Delete(cloudDir, true); } catch { }
        }
    }

    [Fact]
    public async Task DownloadAsync_NoLocal_DownloadsFromCloud()
    {
        var localDir = NewTempDir();
        var cloudDir = NewTempDir();
        try
        {
            var storage = new LocalStorageProvider(cloudDir);
            await storage.WriteAsync("test.db", new MemoryStream("CLOUD-DATA"u8.ToArray()));

            var sync = new CloudSqliteSync(storage,
                new StorageOptions { VolumeDataPath = localDir },
                new DatabaseOptions { BlobKey = "test.db" });

            await sync.DownloadAsync();

            var localContent = await File.ReadAllBytesAsync(Path.Combine(localDir, "test.db"));
            Assert.Equal("CLOUD-DATA"u8.ToArray(), localContent);
        }
        finally
        {
            try { Directory.Delete(localDir, true); } catch { }
            try { Directory.Delete(cloudDir, true); } catch { }
        }
    }

    [Fact]
    public async Task StopAsync_UploadsDirtyDb()
    {
        var localDir = NewTempDir();
        var cloudDir = NewTempDir();
        try
        {
            var storage = new LocalStorageProvider(cloudDir);
            var sync = new CloudSqliteSync(storage,
                new StorageOptions { VolumeDataPath = localDir },
                new DatabaseOptions { BlobKey = "test.db" });

            await File.WriteAllBytesAsync(sync.LocalDbPath, "NEW-DATA"u8.ToArray());
            sync.MarkDirty();

            await sync.StopAsync(CancellationToken.None);

            var cloudData = await storage.ReadAsync("test.db");
            Assert.NotNull(cloudData);
            Assert.Equal("NEW-DATA"u8.ToArray(), cloudData);
        }
        finally
        {
            try { Directory.Delete(localDir, true); } catch { }
            try { Directory.Delete(cloudDir, true); } catch { }
        }
    }

    /// <summary>シャットダウン時アップロード失敗でもローカルが保持され、次回起動で復旧（消失しない）。</summary>
    [Fact]
    public async Task StopAsync_UploadFailure_RetainsLocalForRecovery()
    {
        var localDir = NewTempDir();
        try
        {
            var storage = new FaultyStorageProvider();
            var sync = new CloudSqliteSync(storage,
                new StorageOptions { VolumeDataPath = localDir },
                new DatabaseOptions { BlobKey = "test.db" });

            byte[] precious = "PRECIOUS-UNSAVED-CHANGE"u8.ToArray();
            await File.WriteAllBytesAsync(sync.LocalDbPath, precious);
            sync.MarkDirty();

            // アップロード全失敗。早期キャンセルでリトライ遅延を短縮（失敗時の挙動検証が目的）
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
            await sync.StopAsync(cts.Token);

            // ローカルファイルは保持されている（消失しない）
            Assert.True(File.Exists(sync.LocalDbPath));
            var retained = await File.ReadAllBytesAsync(sync.LocalDbPath);
            Assert.Equal(precious, retained);

            // 次回起動: 同じローカルパスの新しいインスタンスで DownloadAsync は
            // ローカル優先でスキップ → 変更が維持される（再起動後も消失しない）
            var sync2 = new CloudSqliteSync(storage,
                new StorageOptions { VolumeDataPath = localDir },
                new DatabaseOptions { BlobKey = "test.db" });
            await sync2.DownloadAsync();
            var afterReboot = await File.ReadAllBytesAsync(sync2.LocalDbPath);
            Assert.Equal(precious, afterReboot);
        }
        finally
        {
            try { Directory.Delete(localDir, true); } catch { }
        }
    }
}
