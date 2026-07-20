using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;

namespace CistaNAS.Tests;

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
    public async Task RunWithLeaseAsync_LongOperation_KeepsLeaseOwned()
    {
        string dataRoot = Path.Combine(Path.GetTempPath(), "cista-write-lease-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataRoot);
        try
        {
            var storage = new LocalStorageProvider(dataRoot);
            var leases = new E2eeWriteLeaseService(storage,
                leaseDuration: TimeSpan.FromMilliseconds(300),
                renewalInterval: TimeSpan.FromMilliseconds(50));
            string fileId = Guid.NewGuid().ToString("N");
            var lease = await leases.AcquireAsync("test-volume", fileId);

            Task operation = leases.RunWithLeaseAsync("test-volume", fileId, lease.Token,
                ct => Task.Delay(700, ct));
            await Task.Delay(450);

            var conflict = await Assert.ThrowsAsync<E2eeWriteLeaseException>(
                () => leases.AcquireAsync("test-volume", fileId));
            Assert.Equal(LockedStatusCode, conflict.StatusCode);
            await operation;
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
            var storage = new FailLeaseRenewalStorage(new LocalStorageProvider(dataRoot));
            var leases = new E2eeWriteLeaseService(storage,
                leaseDuration: TimeSpan.FromMilliseconds(500),
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

            await Task.Delay(150);
            Assert.False(run.IsCompleted);

            operationMayStop.SetResult();
            await Assert.ThrowsAsync<IOException>(() => run);
        }
        finally
        {
            try { Directory.Delete(dataRoot, recursive: true); }
            catch { }
        }
    }

    private sealed class FailLeaseRenewalStorage(IStorageProvider inner) : IStorageProvider
    {
        public bool FailLeaseWrites { get; set; }

        public Task<byte[]?> ReadAsync(string path, CancellationToken ct = default) => inner.ReadAsync(path, ct);
        public Task WriteAsync(string path, Stream data, CancellationToken ct = default) => inner.WriteAsync(path, data, ct);
        public Task WriteAtomicAsync(string path, Stream data, CancellationToken ct = default)
            => FailLeaseWrites && path.StartsWith(".write-leases/", StringComparison.Ordinal)
                ? Task.FromException(new IOException("simulated lease renewal failure"))
                : inner.WriteAtomicAsync(path, data, ct);
        public Task DeleteAsync(string path, CancellationToken ct = default) => inner.DeleteAsync(path, ct);
        public Task<bool> ExistsAsync(string path, CancellationToken ct = default) => inner.ExistsAsync(path, ct);
        public Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default) => inner.ListAsync(prefix, ct);
        public Task<IDisposable> AcquireLockAsync(string lockPath, CancellationToken ct = default) => inner.AcquireLockAsync(lockPath, ct);
        public void RemoveLock(string lockPath) => inner.RemoveLock(lockPath);
    }
}
