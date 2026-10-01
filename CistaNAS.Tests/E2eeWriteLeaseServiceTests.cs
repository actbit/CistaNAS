using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using System.Text.Json;

namespace CistaNAS.Tests;

[CollectionDefinition("Write lease timing", DisableParallelization = true)]
public sealed class WriteLeaseTimingCollection;

[Collection("Write lease timing")]
public sealed class E2eeWriteLeaseServiceTests
{
    private const int LockedStatusCode = 423;

    [Fact]
    public async Task AcquireAsync_SameFileId_RejectsSecondWriterUntilReleased()
    {
        string dataRoot = Path.Combine(Path.GetTempPath(), "cista-write-lease-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataRoot);
        try
        {
            var leases = new E2eeWriteLeaseService(new LocalStorageProvider(dataRoot));
            const string volumeName = "test-volume";
            string fileId = Guid.NewGuid().ToString("N");

            var first = await leases.AcquireAsync(volumeName, fileId);

            var conflict = await Assert.ThrowsAsync<E2eeWriteLeaseException>(
                () => leases.AcquireAsync(volumeName, fileId));
            Assert.Equal(LockedStatusCode, conflict.StatusCode);

            await leases.ReleaseAsync(volumeName, fileId, first.Token);

            var second = await leases.AcquireAsync(volumeName, fileId);
            Assert.NotEqual(first.Token, second.Token);
        }
        finally
        {
            try { Directory.Delete(dataRoot, recursive: true); }
            catch { }
        }
    }

    [Fact]
    public async Task ValidateAndRenewAsync_WrongToken_IsRejected()
    {
        string dataRoot = Path.Combine(Path.GetTempPath(), "cista-write-lease-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataRoot);
        try
        {
            var leases = new E2eeWriteLeaseService(new LocalStorageProvider(dataRoot));
            string fileId = Guid.NewGuid().ToString("N");
            await leases.AcquireAsync("test-volume", fileId);

            var invalid = await Assert.ThrowsAsync<E2eeWriteLeaseException>(
                () => leases.ValidateAndRenewAsync("test-volume", fileId, "not-the-owner"));

            Assert.Equal(LockedStatusCode, invalid.StatusCode);
        }
        finally
        {
            try { Directory.Delete(dataRoot, recursive: true); }
            catch { }
        }
    }

    [Fact]
    public async Task RunWithLeaseAsync_HeartbeatRenewsLeaseAndKeepsOwnership()
    {
        string dataRoot = Path.Combine(Path.GetTempPath(), "cista-write-lease-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataRoot);
        try
        {
            var storage = new ObservedLeaseStorage(new LocalStorageProvider(dataRoot));
            var leases = new E2eeWriteLeaseService(storage,
                leaseDuration: TimeSpan.FromMinutes(2),
                renewalInterval: TimeSpan.FromMilliseconds(50));
            string fileId = Guid.NewGuid().ToString("N");
            var lease = await leases.AcquireAsync("test-volume", fileId);

            var operationMayFinish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Task operation = leases.RunWithLeaseAsync("test-volume", fileId, lease.Token,
                ct => operationMayFinish.Task.WaitAsync(ct));
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try
            {
                // Wait for a persisted heartbeat rather than assuming that a
                // loaded CI runner executes a timer within a 300 ms lease.
                WriteLease renewed = await storage.HeartbeatCommitted.Task.WaitAsync(timeout.Token);
                Assert.Equal(lease.Token, renewed.Token);
                Assert.True(renewed.ExpiresAt > lease.ExpiresAt);
                var conflict = await Assert.ThrowsAsync<E2eeWriteLeaseException>(
                    () => leases.AcquireAsync("test-volume", fileId));
                Assert.Equal(LockedStatusCode, conflict.StatusCode);
            }
            finally
            {
                operationMayFinish.TrySetResult();
                await operation.WaitAsync(timeout.Token);
            }
        }
        finally
        {
            try { Directory.Delete(dataRoot, recursive: true); }
            catch { }
        }
    }

    [Fact]
    public async Task AcquireAsync_NonCanonicalFileId_IsRejected()
    {
        string dataRoot = Path.Combine(Path.GetTempPath(), "cista-write-lease-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataRoot);
        try
        {
            var leases = new E2eeWriteLeaseService(new LocalStorageProvider(dataRoot));
            const string fileId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            var invalid = await Assert.ThrowsAsync<E2eeWriteLeaseException>(
                () => leases.AcquireAsync("test-volume", fileId.ToUpperInvariant()));
            Assert.Equal(400, invalid.StatusCode);
        }
        finally
        {
            try { Directory.Delete(dataRoot, recursive: true); }
            catch { }
        }
    }

    [Fact]
    public async Task RunWithLeaseAsync_RenewalFailure_WaitsForOperationToStop()
    {
        string dataRoot = Path.Combine(Path.GetTempPath(), "cista-write-lease-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataRoot);
        try
        {
            var storage = new ObservedLeaseStorage(new LocalStorageProvider(dataRoot));
            var leases = new E2eeWriteLeaseService(storage,
                leaseDuration: TimeSpan.FromMinutes(2),
                renewalInterval: TimeSpan.FromMilliseconds(50));
            string fileId = Guid.NewGuid().ToString("N");
            var lease = await leases.AcquireAsync("test-volume", fileId);
            var operationMayStop = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Task run = leases.RunWithLeaseAsync("test-volume", fileId, lease.Token,
                async _ =>
                {
                    storage.FailLeaseWrites = true;
                    await operationMayStop.Task;
                });

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try
            {
                await storage.RenewalFailed.Task.WaitAsync(timeout.Token);
                Assert.False(run.IsCompleted);
            }
            finally { operationMayStop.TrySetResult(); }
            await Assert.ThrowsAsync<IOException>(() => run.WaitAsync(timeout.Token));
        }
        finally
        {
            try { Directory.Delete(dataRoot, recursive: true); }
            catch { }
        }
    }

    private sealed class ObservedLeaseStorage(IStorageProvider inner) : IStorageProvider
    {
        private int _leaseWrites;
        public bool FailLeaseWrites { get; set; }
        public TaskCompletionSource<WriteLease> HeartbeatCommitted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource RenewalFailed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<byte[]?> ReadAsync(string path, CancellationToken ct = default) => inner.ReadAsync(path, ct);
        public Task WriteAsync(string path, Stream data, CancellationToken ct = default) => inner.WriteAsync(path, data, ct);
        public async Task WriteAtomicAsync(string path, Stream data, CancellationToken ct = default)
        {
            bool leaseWrite = path.StartsWith(".write-leases/", StringComparison.Ordinal);
            if (FailLeaseWrites && leaseWrite)
            {
                RenewalFailed.TrySetResult();
                throw new IOException("simulated lease renewal failure");
            }
            await inner.WriteAtomicAsync(path, data, ct);
            // Acquire, initial validation, then the asynchronous heartbeat.
            if (leaseWrite && Interlocked.Increment(ref _leaseWrites) >= 3)
            {
                var persisted = await inner.ReadAsync(path, ct);
                HeartbeatCommitted.TrySetResult(JsonSerializer.Deserialize<WriteLease>(persisted!,
                    new JsonSerializerOptions(JsonSerializerDefaults.Web))!);
            }
        }
        public Task DeleteAsync(string path, CancellationToken ct = default) => inner.DeleteAsync(path, ct);
        public Task<bool> ExistsAsync(string path, CancellationToken ct = default) => inner.ExistsAsync(path, ct);
        public Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default) => inner.ListAsync(prefix, ct);
        public Task<IDisposable> AcquireLockAsync(string lockPath, CancellationToken ct = default) => inner.AcquireLockAsync(lockPath, ct);
        public void RemoveLock(string lockPath) => inner.RemoveLock(lockPath);
    }
}
