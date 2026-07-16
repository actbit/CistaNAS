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
}
