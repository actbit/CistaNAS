using CistaNAS.Web.Storage;

namespace CistaNAS.Tests;

public sealed class StorageLockTests
{
    [Fact]
    public async Task LocalLock_ConcurrentAcquire_WaitsUntilRelease()
    {
        string dataRoot = Path.Combine(Path.GetTempPath(), "cista-storage-lock-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataRoot);
        try
        {
            var storage = new LocalStorageProvider(dataRoot);
            using var first = await storage.AcquireLockAsync("locks/file-id");

            Task<IDisposable> secondTask = storage.AcquireLockAsync("locks/file-id");
            await Task.Delay(150);
            Assert.False(secondTask.IsCompleted);

            first.Dispose();
            using var second = await secondTask.WaitAsync(TimeSpan.FromSeconds(2));
        }
        finally
        {
            try { Directory.Delete(dataRoot, recursive: true); }
            catch { }
        }
    }

    [Fact]
    public async Task LocalLock_WaitingAcquire_ObservesCancellation()
    {
        string dataRoot = Path.Combine(Path.GetTempPath(), "cista-storage-lock-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataRoot);
        try
        {
            var storage = new LocalStorageProvider(dataRoot);
            using var first = await storage.AcquireLockAsync("locks/file-id");
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => storage.AcquireLockAsync("locks/file-id", cts.Token));
        }
        finally
        {
            try { Directory.Delete(dataRoot, recursive: true); }
            catch { }
        }
    }
}
