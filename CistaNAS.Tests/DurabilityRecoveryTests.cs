using System.Text.Json;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public sealed class DurabilityRecoveryTests
{
    [Fact]
    public async Task NewServiceInstanceAfterDispose_MountsAndReadsCommittedChunkData()
    {
        string root = Path.Combine(Path.GetTempPath(), $"cista-durability-{Guid.NewGuid():N}");
        string volumeName = "restart-" + Guid.NewGuid().ToString("N");
        var volumeOptions = CreateChunkOptions();
        var storageOptions = new StorageOptions { Provider = "s3" };
        byte[] expected = Enumerable.Range(0, 9000).Select(i => (byte)(i % 251)).ToArray();

        try
        {
            {
                var first = TestHelper.BuildTestServices(
                    volumeOptions, storageOptions, existingDataRoot: root);
                await using var provider = (ServiceProvider)first.sp;
                var volumes = provider.GetRequiredService<VolumeService>();
                await volumes.CreateAsync(volumeName, "owner", "password");
                await using var scope = provider.CreateAsyncScope();
                var files = scope.ServiceProvider.GetRequiredService<FileService>();
                await files.UploadAsync(volumeName, "committed.bin", new MemoryStream(expected), expected.Length);
                await volumes.LockAsync(volumeName, "owner");
            }

            {
                var second = TestHelper.BuildTestServices(
                    volumeOptions, storageOptions, existingDataRoot: root);
                await using var provider = (ServiceProvider)second.sp;
                var volumes = provider.GetRequiredService<VolumeService>();
                await volumes.MountAsync(volumeName, "owner", "password");
                await using var scope = provider.CreateAsyncScope();
                var files = scope.ServiceProvider.GetRequiredService<FileService>();
                var response = await files.DownloadAsync(volumeName, "committed.bin");
                await using var stream = response.Stream;
                using var actual = new MemoryStream();
                await stream.CopyToAsync(actual);
                Assert.Equal(expected, actual.ToArray());
                await volumes.LockAsync(volumeName, "owner");
            }
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task BackgroundAuditProcessesFilesIncrementallyAfterMount()
    {
        var volumeOptions = CreateChunkOptions();
        volumeOptions.IntegrityAuditBatchSize = 1;
        volumeOptions.IntegrityAuditIntervalMinutes = 1;
        var (serviceProvider, dataRoot) = TestHelper.BuildTestServices(
            volumeOptions, new StorageOptions { Provider = "s3" });
        await using var provider = (ServiceProvider)serviceProvider;
        try
        {
            var volumes = provider.GetRequiredService<VolumeService>();
            string volumeName = "audit-" + Guid.NewGuid().ToString("N");
            await volumes.CreateAsync(volumeName, "owner", "password");
            await using (var scope = provider.CreateAsyncScope())
            {
                var files = scope.ServiceProvider.GetRequiredService<FileService>();
                await files.UploadAsync(volumeName, "damaged.bin", new MemoryStream(new byte[9000]), 9000);
            }

            await using (var scope = provider.CreateAsyncScope())
            {
                var files = scope.ServiceProvider.GetRequiredService<FileService>();
                var metadata = Assert.Single((await files.ListAsync(volumeName)).Files);
                string objectId = Assert.IsType<string>(metadata.ChunkObjectId);
                var storage = provider.GetRequiredService<IStorageProvider>();
                await storage.DeleteAsync($"{volumeName}/chunks/{objectId}/00001");
            }

            var audit = new VolumeIntegrityAuditService(
                volumes,
                provider.GetRequiredService<IServiceScopeFactory>(),
                provider.GetRequiredService<IOptions<CistaNasOptions>>(),
                provider.GetRequiredService<ILogger<VolumeIntegrityAuditService>>());
            await audit.RunOnceAsync();

            await using var verifyScope = provider.CreateAsyncScope();
            var verifyFiles = verifyScope.ServiceProvider.GetRequiredService<FileService>();
            Assert.True(Assert.Single((await verifyFiles.ListAsync(volumeName)).Files).NeedsRepair);
            await volumes.LockAsync(volumeName, "owner");
        }
        finally
        {
            if (Directory.Exists(dataRoot)) Directory.Delete(dataRoot, recursive: true);
        }
    }

    [Fact]
    public async Task BackgroundAuditCursorResumesAfterServiceRecreation()
    {
        var volumeOptions = CreateChunkOptions();
        volumeOptions.IntegrityAuditBatchSize = 1;
        var (serviceProvider, dataRoot) = TestHelper.BuildTestServices(
            volumeOptions, new StorageOptions { Provider = "s3" });
        await using var provider = (ServiceProvider)serviceProvider;
        try
        {
            var volumes = provider.GetRequiredService<VolumeService>();
            string volumeName = "audit-resume-" + Guid.NewGuid().ToString("N");
            await volumes.CreateAsync(volumeName, "owner", "password");
            await using (var scope = provider.CreateAsyncScope())
            {
                var files = scope.ServiceProvider.GetRequiredService<FileService>();
                await files.UploadAsync(volumeName, "a.bin", new MemoryStream(new byte[9000]), 9000);
                await files.UploadAsync(volumeName, "b.bin", new MemoryStream(new byte[9000]), 9000);
            }

            var storage = provider.GetRequiredService<IStorageProvider>();
            await using (var scope = provider.CreateAsyncScope())
            {
                var files = scope.ServiceProvider.GetRequiredService<FileService>();
                var b = (await files.ListAsync(volumeName)).Files.Single(file => file.Name == "b.bin");
                await storage.DeleteAsync($"{volumeName}/chunks/{b.ChunkObjectId}/00001");
            }

            VolumeIntegrityAuditService NewAudit() => new(
                volumes,
                provider.GetRequiredService<IServiceScopeFactory>(),
                provider.GetRequiredService<IOptions<CistaNasOptions>>(),
                provider.GetRequiredService<ILogger<VolumeIntegrityAuditService>>());

            await NewAudit().RunOnceAsync(); // a.bin を処理してカーソルを保存
            await using (var scope = provider.CreateAsyncScope())
            {
                var files = scope.ServiceProvider.GetRequiredService<FileService>();
                Assert.False((await files.ListAsync(volumeName)).Files.Single(file => file.Name == "b.bin").NeedsRepair);
            }

            await NewAudit().RunOnceAsync(); // 再生成後も b.bin から継続
            await using (var scope = provider.CreateAsyncScope())
            {
                var files = scope.ServiceProvider.GetRequiredService<FileService>();
                Assert.True((await files.ListAsync(volumeName)).Files.Single(file => file.Name == "b.bin").NeedsRepair);
            }
            await volumes.LockAsync(volumeName, "owner");
        }
        finally
        {
            if (Directory.Exists(dataRoot)) Directory.Delete(dataRoot, recursive: true);
        }
    }

    [Fact]
    public async Task ScheduledGcRemovesOnlyExpiredOrphanChunks()
    {
        var volumeOptions = CreateChunkOptions();
        volumeOptions.ChunkGcHoldHours = 1;
        volumeOptions.ChunkGcIntervalMinutes = 1;
        var (serviceProvider, dataRoot) = TestHelper.BuildTestServices(
            volumeOptions, new StorageOptions { Provider = "s3" });
        await using var provider = (ServiceProvider)serviceProvider;
        try
        {
            var volumes = provider.GetRequiredService<VolumeService>();
            string volumeName = "gc-" + Guid.NewGuid().ToString("N");
            await volumes.CreateAsync(volumeName, "owner", "password");
            var storage = provider.GetRequiredService<IStorageProvider>();
            string objectId = "expired-orphan";
            await storage.WriteAsync(
                $"{volumeName}/chunks/{objectId}/00000", new MemoryStream([9, 8, 7]));

            using (var ledger = new MemoryStream())
            {
                JsonSerializer.Serialize(ledger, new Dictionary<string, DateTimeOffset>
                {
                    [objectId] = DateTimeOffset.UtcNow.AddHours(-2),
                });
                ledger.Position = 0;
                await storage.WriteAtomicAsync($"{volumeName}/chunk-gc-candidates.json", ledger);
            }

            var gc = new ChunkGarbageCollectionService(
                volumes,
                provider.GetRequiredService<IServiceScopeFactory>(),
                provider.GetRequiredService<IOptions<CistaNasOptions>>(),
                provider.GetRequiredService<ILogger<ChunkGarbageCollectionService>>());
            await gc.RunOnceAsync();

            Assert.Null(await storage.ReadAsync($"{volumeName}/chunks/{objectId}/00000"));
            await volumes.LockAsync(volumeName, "owner");
        }
        finally
        {
            if (Directory.Exists(dataRoot)) Directory.Delete(dataRoot, recursive: true);
        }
    }

    [Fact]
    public async Task ScheduledGcProcessesUnmountedChunkVolume()
    {
        var volumeOptions = CreateChunkOptions();
        volumeOptions.ChunkGcHoldHours = 1;
        var (serviceProvider, dataRoot) = TestHelper.BuildTestServices(
            volumeOptions, new StorageOptions { Provider = "s3" });
        await using var provider = (ServiceProvider)serviceProvider;
        try
        {
            var volumes = provider.GetRequiredService<VolumeService>();
            string volumeName = "gc-unmounted-" + Guid.NewGuid().ToString("N");
            await volumes.CreateAsync(volumeName, "owner", "password");
            await volumes.LockAsync(volumeName, "owner");

            var storage = provider.GetRequiredService<IStorageProvider>();
            string objectId = "unmounted-orphan";
            await storage.WriteAsync(
                $"{volumeName}/chunks/{objectId}/00000", new MemoryStream([4, 5, 6]));
            using (var ledger = new MemoryStream())
            {
                JsonSerializer.Serialize(ledger, new Dictionary<string, DateTimeOffset>
                {
                    [objectId] = DateTimeOffset.UtcNow.AddHours(-2),
                });
                ledger.Position = 0;
                await storage.WriteAtomicAsync($"{volumeName}/chunk-gc-candidates.json", ledger);
            }

            var gc = new ChunkGarbageCollectionService(
                volumes,
                provider.GetRequiredService<IServiceScopeFactory>(),
                provider.GetRequiredService<IOptions<CistaNasOptions>>(),
                provider.GetRequiredService<ILogger<ChunkGarbageCollectionService>>());
            await gc.RunOnceAsync();

            Assert.Null(await storage.ReadAsync($"{volumeName}/chunks/{objectId}/00000"));
        }
        finally
        {
            if (Directory.Exists(dataRoot)) Directory.Delete(dataRoot, recursive: true);
        }
    }

    [Fact]
    public async Task ScheduledGcStorageOutageKeepsCandidateForRetry()
    {
        var volumeOptions = CreateChunkOptions();
        volumeOptions.ChunkGcHoldHours = 1;
        FailingDeleteStorage? failingStorage = null;
        var (serviceProvider, dataRoot) = TestHelper.BuildTestServices(
            volumeOptions,
            new StorageOptions { Provider = "s3" },
            root => failingStorage = new FailingDeleteStorage(root));
        await using var provider = (ServiceProvider)serviceProvider;
        try
        {
            var volumes = provider.GetRequiredService<VolumeService>();
            Assert.NotNull(failingStorage);
            string volumeName = "gc-outage-" + Guid.NewGuid().ToString("N");
            await volumes.CreateAsync(volumeName, "owner", "password");
            string objectId = "retry-orphan";
            await failingStorage!.WriteAsync(
                $"{volumeName}/chunks/{objectId}/00000", new MemoryStream([1, 2, 3]));
            using (var ledger = new MemoryStream())
            {
                JsonSerializer.Serialize(ledger, new Dictionary<string, DateTimeOffset>
                {
                    [objectId] = DateTimeOffset.UtcNow.AddHours(-2),
                });
                ledger.Position = 0;
                await failingStorage.WriteAtomicAsync(
                    $"{volumeName}/chunk-gc-candidates.json", ledger);
            }

            var gc = new ChunkGarbageCollectionService(
                volumes,
                provider.GetRequiredService<IServiceScopeFactory>(),
                provider.GetRequiredService<IOptions<CistaNasOptions>>(),
                provider.GetRequiredService<ILogger<ChunkGarbageCollectionService>>());
            failingStorage.FailDeletes = 100;
            await gc.RunOnceAsync();
            Assert.NotNull(await failingStorage.ReadAsync(
                $"{volumeName}/chunks/{objectId}/00000"));

            failingStorage.FailDeletes = 0;
            await gc.RunOnceAsync();
            Assert.Null(await failingStorage.ReadAsync(
                $"{volumeName}/chunks/{objectId}/00000"));
            await volumes.LockAsync(volumeName, "owner");
        }
        finally
        {
            if (Directory.Exists(dataRoot)) Directory.Delete(dataRoot, recursive: true);
        }
    }

    private static VolumeOptions CreateChunkOptions() => new()
    {
        ChunkStorage = "auto",
        ServerChunkSize = 4096,
        SectorSize = 512,
        KdfIterations = 10_000,
        KdfMemoryKiB = 8192,
        KdfTimeCost = 1,
        KdfParallelism = 1,
    };

    private sealed class FailingDeleteStorage(string root) : IStorageProvider
    {
        private readonly LocalStorageProvider _inner = new(root);
        public int FailDeletes;
        public string RecoveryIdentity => _inner.RecoveryIdentity;
        public Task<byte[]?> ReadAsync(string path, CancellationToken ct = default)
            => _inner.ReadAsync(path, ct);
        public Task WriteAsync(string path, Stream content, CancellationToken ct = default)
            => _inner.WriteAsync(path, content, ct);
        public Task WriteAtomicAsync(string path, Stream content, CancellationToken ct = default)
            => _inner.WriteAtomicAsync(path, content, ct);
        public Task DeleteAsync(string path, CancellationToken ct = default)
        {
            if (path.Contains("/chunks/", StringComparison.Ordinal)
                && Interlocked.Decrement(ref FailDeletes) >= 0)
                return Task.FromException(new IOException("simulated object storage outage"));
            return _inner.DeleteAsync(path, ct);
        }
        public Task<bool> ExistsAsync(string path, CancellationToken ct = default)
            => _inner.ExistsAsync(path, ct);
        public Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default)
            => _inner.ListAsync(prefix, ct);
        public Task<IDisposable> AcquireLockAsync(string path, CancellationToken ct = default)
            => _inner.AcquireLockAsync(path, ct);
        public void RemoveLock(string path) => _inner.RemoveLock(path);
    }
}
