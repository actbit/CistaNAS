using CistaNAS.Web.Configuration;
using CistaNAS.Web.Storage;
using Microsoft.Data.Sqlite;

namespace CistaNAS.Tests;

public sealed class CloudSqliteRecoveryTests
{
    [Fact]
    public async Task FailedSync_RestartWithoutAnotherWrite_ResendsLocalDatabase()
    {
        using var fixture = new Fixture();
        using (var sync = fixture.CreateSync())
        {
            WriteValue(sync.LocalDbPath, "unsynced");
            fixture.Storage.FailWrites = 1;
            sync.MarkDirty();
            await Assert.ThrowsAsync<IOException>(() => sync.UploadIfDirtyAsync());
        }
        using var restarted = fixture.CreateSync();
        await restarted.DownloadAsync();
        await restarted.UploadIfDirtyAsync();
        Assert.Equal("unsynced", await fixture.CloudValueAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TemporaryDatabase_FailedOrCancelledShutdownAndDispose_RetainsRecoveryCopy(bool cancelled)
    {
        using var fixture = new Fixture();
        string key = $"cista-recovery-{Guid.NewGuid():N}.db";
        var sync = new CloudSqliteSync(fixture.Storage, new StorageOptions(), new DatabaseOptions { BlobKey = key });
        try
        {
            WriteValue(sync.LocalDbPath, "precious");
            sync.MarkDirty();
            fixture.Storage.FailWrites = 100;
            using var cts = new CancellationTokenSource();
            if (cancelled) cts.Cancel();
            else cts.CancelAfter(100);
            await sync.StopAsync(cts.Token);
            sync.Dispose();
            Assert.True(File.Exists(sync.LocalDbPath));
            using var db = Open(sync.LocalDbPath);
            Assert.Equal("precious", ReadValue(db));
        }
        finally
        {
            sync.Dispose();
            File.Delete(sync.LocalDbPath);
        }
    }

    [Fact]
    public async Task Sync_IncludesCommittedWalData_WhileConnectionRemainsOpen()
    {
        using var fixture = new Fixture();
        using var sync = fixture.CreateSync();
        using var db = Open(sync.LocalDbPath);
        Execute(db, "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;");
        WriteValue(db, "committed-in-wal");
        Assert.True(File.Exists(sync.LocalDbPath + "-wal"));
        sync.MarkDirty();
        await sync.UploadIfDirtyAsync();
        Assert.Equal("committed-in-wal", await fixture.CloudValueAsync());
        Assert.Empty(Directory.GetFiles(fixture.Local, "*.snapshot-*"));
    }

    [Fact]
    public async Task ConcurrentSyncs_CannotPublishOlderSnapshotAfterNewerOne()
    {
        using var fixture = new Fixture();
        using var sync = fixture.CreateSync();
        WriteValue(sync.LocalDbPath, "old");
        sync.MarkDirty();
        fixture.Storage.BlockFirstWrite = true;
        var first = sync.UploadIfDirtyAsync();
        await fixture.Storage.FirstWriteCaptured.Task.WaitAsync(TimeSpan.FromSeconds(5));
        WriteValue(sync.LocalDbPath, "new");
        sync.MarkDirty();
        var second = sync.UploadIfDirtyAsync();
        try
        {
            await Task.Delay(100);
            Assert.False(second.IsCompleted);
        }
        finally
        {
            fixture.Storage.ReleaseFirstWrite.TrySetResult();
            await Task.WhenAll(first, second);
        }
        Assert.Equal("new", await fixture.CloudValueAsync());
    }

    [Fact]
    public async Task HostedSync_RetriesDuringOperation_WithoutWaitingForShutdown()
    {
        using var fixture = new Fixture();
        using var sync = fixture.CreateSync();
        WriteValue(sync.LocalDbPath, "live");
        fixture.Storage.FailWrites = 1;
        sync.MarkDirty();
        await sync.StartAsync(CancellationToken.None);
        try
        {
            await fixture.Storage.SuccessfulWrite.Task.WaitAsync(TimeSpan.FromSeconds(8));
            Assert.Equal("live", await fixture.CloudValueAsync());
        }
        finally { await sync.StopAsync(CancellationToken.None); }
    }

    internal static SqliteConnection Open(string path)
    {
        var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        db.Open();
        return db;
    }

    internal static void WriteValue(string path, string value)
    {
        using var db = Open(path);
        WriteValue(db, value);
    }

    private static void WriteValue(SqliteConnection db, string value)
    {
        Execute(db, "CREATE TABLE IF NOT EXISTS recovery(value TEXT NOT NULL); DELETE FROM recovery;");
        using var command = db.CreateCommand();
        command.CommandText = "INSERT INTO recovery(value) VALUES ($value)";
        command.Parameters.AddWithValue("$value", value);
        command.ExecuteNonQuery();
    }

    internal static string ReadValue(SqliteConnection db)
    {
        using var command = db.CreateCommand();
        command.CommandText = "SELECT value FROM recovery";
        return (string)command.ExecuteScalar()!;
    }

    private static void Execute(SqliteConnection db, string sql)
    {
        using var command = db.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), $"cista-sync-{Guid.NewGuid():N}");
        public string Local => Path.Combine(_root, "local");
        public ControlledStorage Storage { get; }
        public Fixture()
        {
            Directory.CreateDirectory(Local);
            Storage = new ControlledStorage(Path.Combine(_root, "cloud"));
        }
        public CloudSqliteSync CreateSync() => new(Storage, new StorageOptions { VolumeDataPath = Local },
            new DatabaseOptions { BlobKey = "test.db", SyncIntervalSeconds = 1 });
        public async Task<string> CloudValueAsync()
        {
            byte[]? bytes = await Storage.ReadAsync("test.db");
            Assert.NotNull(bytes);
            string path = Path.Combine(_root, $"verify-{Guid.NewGuid():N}.db");
            await File.WriteAllBytesAsync(path, bytes);
            using var db = Open(path);
            using var check = db.CreateCommand();
            check.CommandText = "PRAGMA integrity_check";
            Assert.Equal("ok", check.ExecuteScalar());
            return ReadValue(db);
        }
        public void Dispose() => Directory.Delete(_root, true);
    }

    private sealed class ControlledStorage(string root) : IStorageProvider
    {
        private readonly LocalStorageProvider _inner = new(root);
        private int _writes;
        public int FailWrites;
        public bool BlockFirstWrite;
        public TaskCompletionSource FirstWriteCaptured { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseFirstWrite { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource SuccessfulWrite { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<byte[]?> ReadAsync(string p, CancellationToken ct = default) => _inner.ReadAsync(p, ct);
        public Task WriteAsync(string p, Stream s, CancellationToken ct = default) => _inner.WriteAsync(p, s, ct);
        public async Task WriteAtomicAsync(string p, Stream s, CancellationToken ct = default)
        {
            int count = Interlocked.Increment(ref _writes);
            if (Interlocked.Decrement(ref FailWrites) >= 0) throw new IOException("simulated outage");
            using var captured = new MemoryStream();
            await s.CopyToAsync(captured, ct);
            if (BlockFirstWrite && count == 1)
            {
                FirstWriteCaptured.TrySetResult();
                await ReleaseFirstWrite.Task.WaitAsync(ct);
            }
            captured.Position = 0;
            await _inner.WriteAtomicAsync(p, captured, ct);
            SuccessfulWrite.TrySetResult();
        }
        public Task DeleteAsync(string p, CancellationToken ct = default) => _inner.DeleteAsync(p, ct);
        public Task<bool> ExistsAsync(string p, CancellationToken ct = default) => _inner.ExistsAsync(p, ct);
        public Task<IReadOnlyList<string>> ListAsync(string? p, CancellationToken ct = default) => _inner.ListAsync(p, ct);
        public Task<IDisposable> AcquireLockAsync(string p, CancellationToken ct = default) => _inner.AcquireLockAsync(p, ct);
        public void RemoveLock(string p) => _inner.RemoveLock(p);
    }
}
