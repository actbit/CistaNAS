using System.Text;
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
    public async Task E2eeCreate_RejectsOversizedEncryptedNameBeforeCatalogWrite()
    {
        await _volumes.CreateE2eeAsync(
            "name-limit", "alice", new VolumeHeader.UserWrappedKey());
        using var scope = _services.CreateScope();
        var files = scope.ServiceProvider.GetRequiredService<E2eeFileService>();

        await Assert.ThrowsAsync<FileServiceException>(() => files.CreateFileAsync(
            "name-limit",
            new E2eeCreateFileRequest(new string('A', 4097), E2eeFileService.SaltSize + E2eeFileService.TagSize, 1),
            "alice"));

        var catalog = _services.GetRequiredService<IStorageProvider>();
        Assert.False(await catalog.ExistsAsync("name-limit/catalog-e2ee.json"));
    }

    [Fact]
    public async Task LegacyE2ee_RejectsVariableLengthReplacementWithoutChangingBytes()
    {
        const string volumeName = "legacy-shape";
        await _volumes.CreateE2eeAsync(volumeName, "alice", new VolumeHeader.UserWrappedKey());
        await _volumes.LockAsync(volumeName, "alice");

        var metadata = _services.GetRequiredService<VolumeMetadataStore>();
        var header = await metadata.LoadAsync(volumeName);
        Assert.NotNull(header);
        header!.StorageMode = "local";
        await metadata.SaveAsync(volumeName, header);
        File.Create(Path.Combine(_dataRoot, volumeName, "volume.dat")).Dispose();
        await _volumes.MountE2eeAsync(volumeName, "alice");

        using var scope = _services.CreateScope();
        var files = scope.ServiceProvider.GetRequiredService<E2eeFileService>();
        var entry = await files.CreateFileAsync(
            volumeName, new E2eeCreateFileRequest("legacy", 32, 1), "alice");
        using (var original = new MemoryStream(new byte[32]))
            await files.UploadChunkAsync(volumeName, entry.FileId, 0, original, 32);

        using var replacement = new MemoryStream(new byte[33]);
        await Assert.ThrowsAsync<FileServiceException>(() => files.UploadChunkAsync(
            volumeName, entry.FileId, 0, replacement, 33, replace: true));

        var current = Assert.Single((await files.ListFilesAsync(volumeName)).Files);
        Assert.Equal(32, current.ChunkSizes[0]);
    }

    [Fact]
    public async Task PublicKeyUpdate_RejectsMalformedOrOversizedValues()
    {
        using var scope = _services.CreateScope();
        var account = scope.ServiceProvider.GetRequiredService<AccountService>();
        await account.CreateUserAsync("key-bound", "password1234", "user");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            account.UpdatePublicKeyAsync("key-bound", new string('A', 257)));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            account.UpdatePublicKeyAsync("key-bound", Convert.ToBase64String(new byte[32])));
    }

    [Fact]
    public void InvitationAcceptedData_RejectsOversizedPayloads()
    {
        var invitations = new InvitationService();
        var invitation = invitations.Create("alice", "bob");

        Assert.Throws<InvalidOperationException>(() => invitations.SetAcceptedData(
            invitation.InvitationId, new string('A', 513), "nonce"));
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
    public async Task HomeVolume_IsAccessibleOnlyByItsOwner()
    {
        const string home = "home__alice";
        await _volumes.CreateInternalAsync(home, "alice", null, encrypted: false);

        Assert.True(await _volumes.HasAccessAsync(home, "alice"));
        Assert.False(await _volumes.HasAccessAsync(home, "bob"));

        await _volumes.LockAsync(home, "alice");
        await Assert.ThrowsAsync<VolumeException>(() => _volumes.MountAsync(home, "bob", null));
    }

    [Fact]
    public async Task CreateUser_DoesNotReuseAnExistingHomeVolume()
    {
        await _volumes.CreateInternalAsync("home__reused", "old-user", null, encrypted: false);

        using var scope = _services.CreateScope();
        var account = scope.ServiceProvider.GetRequiredService<AccountService>();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            account.CreateUserAsync("reused", "password1234", "user"));

        Assert.Null(await account.FindAsync("reused"));
    }

    [Fact]
    public async Task OwnedVolumeEnumeration_FailsClosedOnCorruptHeader()
    {
        await _volumes.CreateInternalAsync("owned-corrupt", "alice", null, encrypted: false);
        await _volumes.LockAsync("owned-corrupt", "alice");

        var metadata = _services.GetRequiredService<VolumeMetadataStore>();
        var originalHeader = await metadata.LoadAsync("owned-corrupt");
        Assert.NotNull(originalHeader);

        var storage = _services.GetRequiredService<IStorageProvider>();
        await storage.WriteAsync(
            "owned-corrupt/volume.json",
            new MemoryStream(Encoding.UTF8.GetBytes("{")));

        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                _volumes.GetOwnedVolumeNamesAsync("alice"));
        }
        finally
        {
            await metadata.SaveAsync("owned-corrupt", originalHeader!);
        }
    }

    [Fact]
    public async Task DeletingAndRecreatingGroup_DoesNotReuseOldVolumeAccess()
    {
        const string groupName = "reusable-group";
        using var scope = _services.CreateScope();
        var groups = scope.ServiceProvider.GetRequiredService<GroupService>();

        await groups.CreateGroupAsync(groupName, "alice");
        await groups.AddMemberAsync(groupName, "alice", "bob");
        await _volumes.CreateAsync("group-access", "alice", "password", encrypted: true);
        await _volumes.GrantGroupAccessAsync("group-access", "alice", groupName);
        Assert.True(await _volumes.HasAccessAsync("group-access", "bob"));

        await groups.DeleteGroupAsync(groupName, "alice");
        await groups.CreateGroupAsync(groupName, "alice");
        await groups.AddMemberAsync(groupName, "alice", "bob");

        Assert.False(await _volumes.HasAccessAsync("group-access", "bob"));
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
