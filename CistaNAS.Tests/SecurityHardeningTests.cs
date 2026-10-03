using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;

namespace CistaNAS.Tests;

public sealed class SecurityHardeningTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _services;
    private readonly VolumeService _volumes;

    public SecurityHardeningTests()
    {
        (_services, _dataRoot) = TestHelper.BuildTestServices();
        _volumes = _services.GetRequiredService<VolumeService>();
    }

    [Fact]
    public async Task E2eeCreate_RejectsOversizedChunkSizeBeforePersistingMetadata()
    {
        await Assert.ThrowsAsync<VolumeException>(() => _volumes.CreateE2eeAsync(
            "invalid-e2ee", "alice", new VolumeHeader.UserWrappedKey(), 67_108_865));

        var storage = _services.GetRequiredService<IStorageProvider>();
        Assert.False(await storage.ExistsAsync("invalid-e2ee/volume.json"));
    }

    [Fact]
    public async Task E2eeCreate_UsesChunkStorageWithoutCreatingAStaleVolumeFile()
    {
        await _volumes.CreateE2eeAsync(
            "chunk-e2ee", "alice", new VolumeHeader.UserWrappedKey());

        Assert.False(File.Exists(Path.Combine(_dataRoot, "chunk-e2ee", "volume.dat")));
        Assert.True(_volumes.IsChunkMode("chunk-e2ee"));
    }

    [Fact]
    public async Task GroupCreate_RejectsPathSeparators()
    {
        using var scope = _services.CreateScope();
        var groups = scope.ServiceProvider.GetRequiredService<GroupService>();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            groups.CreateGroupAsync("../outside", "alice"));
    }

    [Fact]
    public async Task InternalVolumeCreate_RejectsPathSeparators()
    {
        await Assert.ThrowsAsync<VolumeException>(() =>
            _volumes.CreateInternalAsync("../outside", "alice", null, encrypted: false));
    }

    [Fact]
    public async Task DeleteVolume_PropagatesMetadataFailureAndKeepsHeaderForRetry()
    {
        bool failHeaderDelete = true;
        var (services, dataRoot) = TestHelper.BuildTestServices(
            storageFactory: root => new FailingDeleteStorage(
                new LocalStorageProvider(root), () => failHeaderDelete));
        var volumes = services.GetRequiredService<VolumeService>();

        try
        {
            await volumes.CreateAsync("delete-retry", "alice", "password", encrypted: true);

            await Assert.ThrowsAsync<IOException>(() =>
                volumes.DeleteVolumeAsync("delete-retry", "alice"));

            Assert.False(volumes.IsMounted("delete-retry"));
            var storage = services.GetRequiredService<IStorageProvider>();
            Assert.True(await storage.ExistsAsync("delete-retry/volume.json"));

            failHeaderDelete = false;
            await volumes.DeleteVolumeAsync("delete-retry", "alice");
            Assert.False(await storage.ExistsAsync("delete-retry/volume.json"));
        }
        finally
        {
            if (services is IAsyncDisposable disposable)
                await disposable.DisposeAsync();
            if (Directory.Exists(dataRoot))
                Directory.Delete(dataRoot, recursive: true);
        }
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var volume in await _volumes.ListAllAsync())
        {
            try
            {
                if (_volumes.IsMounted(volume.Name))
                    await _volumes.LockAsync(volume.Name, volume.OwnerUser);
            }
            catch
            {
                // Test cleanup must not hide the assertion failure.
            }
        }

        if (_services is IAsyncDisposable disposable)
            await disposable.DisposeAsync();
        if (Directory.Exists(_dataRoot))
            Directory.Delete(_dataRoot, recursive: true);
    }

    private sealed class FailingDeleteStorage(
        IStorageProvider inner,
        Func<bool> shouldFailHeaderDelete) : IStorageProvider
    {
        public string RecoveryIdentity => inner.RecoveryIdentity;

        public Task<byte[]?> ReadAsync(string blobPath, CancellationToken ct = default)
            => inner.ReadAsync(blobPath, ct);

        public Task WriteAsync(string blobPath, Stream content, CancellationToken ct = default)
            => inner.WriteAsync(blobPath, content, ct);

        public Task WriteAtomicAsync(string blobPath, Stream content, CancellationToken ct = default)
            => inner.WriteAtomicAsync(blobPath, content, ct);

        public Task DeleteAsync(string blobPath, CancellationToken ct = default)
        {
            if (shouldFailHeaderDelete()
                && blobPath.EndsWith("/volume.json", StringComparison.Ordinal))
                return Task.FromException(new IOException("simulated metadata deletion failure"));
            return inner.DeleteAsync(blobPath, ct);
        }

        public Task<bool> ExistsAsync(string blobPath, CancellationToken ct = default)
            => inner.ExistsAsync(blobPath, ct);

        public Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default)
            => inner.ListAsync(prefix, ct);

        public Task<IDisposable> AcquireLockAsync(string lockPath, CancellationToken ct = default)
            => inner.AcquireLockAsync(lockPath, ct);

        public void RemoveLock(string lockPath) => inner.RemoveLock(lockPath);
    }
}
