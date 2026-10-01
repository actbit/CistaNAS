using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public partial class E2eeFileTests
{
    [Fact]
    public async Task ReplacingPendingChunk_KeepsOnlyVisibleAndLatestPendingGenerations()
    {
        _sp.GetRequiredService<IOptions<CistaNasOptions>>().Value.Storage.Provider = "s3";
        string volume = await MountE2eeAsync("pending-cleanup");
        var service = GetE2eeFileService();
        var storage = _sp.GetRequiredService<IStorageProvider>();
        var entry = await service.CreateFileAsync(volume, new E2eeCreateFileRequest("enc", 100, 1), "testuser");
        await Upload(new byte[100], false);
        for (byte revision = 1; revision <= 6; revision++)
        {
            await Upload(Enumerable.Repeat(revision, 100).ToArray(), true);
            Assert.Equal(2, (await storage.ListAsync($"{volume}/chunks/{entry.FileId}/versions/")).Count);
            var (visible, _, _, _) = await service.DownloadChunkAsync(volume, entry.FileId, 0);
            using (visible)
            {
                byte[] bytes = new byte[100];
                await visible.ReadExactlyAsync(bytes);
                Assert.Equal(new byte[100], bytes);
            }
        }
        await service.FinalizeFileAsync(volume, entry.FileId, new E2eeFinalizeFileRequest(100, 1));
        Assert.Single(await storage.ListAsync($"{volume}/chunks/{entry.FileId}/versions/"));
        var (latest, _, revisionNumber, _) = await service.DownloadChunkAsync(volume, entry.FileId, 0);
        using (latest)
        {
            byte[] bytes = new byte[100];
            await latest.ReadExactlyAsync(bytes);
            Assert.Equal(Enumerable.Repeat((byte)6, 100), bytes);
            Assert.Equal(6, revisionNumber);
        }
        await service.DeleteFileAsync(volume, entry.FileId);
        Assert.Empty(await storage.ListAsync($"{volume}/chunks/{entry.FileId}/"));

        async Task Upload(byte[] bytes, bool replace)
        {
            using var content = new MemoryStream(bytes);
            await service.UploadChunkAsync(volume, entry.FileId, 0, content, bytes.Length, replace);
        }
    }

    [Fact]
    public async Task FailedPendingReplacement_PreservesPreviouslyStagedData()
    {
        _sp.GetRequiredService<IOptions<CistaNasOptions>>().Value.Storage.Provider = "s3";
        string volume = await MountE2eeAsync("pending-save-failure");
        var service = GetE2eeFileService();
        var storage = _sp.GetRequiredService<IStorageProvider>();
        var chunks = _sp.GetRequiredService<IChunkStore>();
        var entry = await service.CreateFileAsync(volume, new E2eeCreateFileRequest("enc", 100, 1), "testuser");
        using (var initial = new MemoryStream(new byte[100]))
            await service.UploadChunkAsync(volume, entry.FileId, 0, initial, 100);
        byte[] expected = Enumerable.Repeat((byte)42, 100).ToArray();
        using (var pending = new MemoryStream(expected))
            await service.UploadChunkAsync(volume, entry.FileId, 0, pending, 100, replace: true);
        var before = await storage.ListAsync($"{volume}/chunks/{entry.FileId}/versions/");
        var failingService = new E2eeFileService(_volumeService,
            new FailCatalogWriteStorage(storage) { FailCatalogWrites = true }, chunks,
            _sp.GetRequiredService<IOptions<CistaNasOptions>>());
        using (var replacement = new MemoryStream(new byte[100]))
            await Assert.ThrowsAsync<IOException>(() =>
                failingService.UploadChunkAsync(volume, entry.FileId, 0, replacement, 100, replace: true));
        Assert.Equal(before.Order(), (await storage.ListAsync($"{volume}/chunks/{entry.FileId}/versions/")).Order());
        await service.FinalizeFileAsync(volume, entry.FileId, new E2eeFinalizeFileRequest(100, 1));
        var (visible, _, _, _) = await service.DownloadChunkAsync(volume, entry.FileId, 0);
        using (visible)
        {
            byte[] actual = new byte[100];
            await visible.ReadExactlyAsync(actual);
            Assert.Equal(expected, actual);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Finalize_RetriesOldGenerationDeletionAfterPublication(bool cancelAfterSave)
    {
        _sp.GetRequiredService<IOptions<CistaNasOptions>>().Value.Storage.Provider = "s3";
        string volume = await MountE2eeAsync("finalize-cleanup");
        var storage = _sp.GetRequiredService<IStorageProvider>();
        var chunks = new TransientCleanupStore(_sp.GetRequiredService<IChunkStore>());
        using var cancellation = new CancellationTokenSource();
        var guardedStorage = new CancelAfterCatalogStorage(storage, cancellation);
        var service = new E2eeFileService(_volumeService, guardedStorage, chunks,
            _sp.GetRequiredService<IOptions<CistaNasOptions>>());
        var entry = await service.CreateFileAsync(volume, new E2eeCreateFileRequest("enc", 100, 1), "testuser");
        using (var initial = new MemoryStream(new byte[100]))
            await service.UploadChunkAsync(volume, entry.FileId, 0, initial, 100);
        using (var replacement = new MemoryStream(new byte[100]))
            await service.UploadChunkAsync(volume, entry.FileId, 0, replacement, 100, replace: true);
        chunks.FailNextDelete = true;
        guardedStorage.CancelAfterSave = cancelAfterSave;
        await service.FinalizeFileAsync(volume, entry.FileId, new E2eeFinalizeFileRequest(100, 1), cancellation.Token);
        Assert.Single(await storage.ListAsync($"{volume}/chunks/{entry.FileId}/versions/"));
        Assert.Equal(2, chunks.DeleteAttempts);
    }

    [Fact]
    public async Task FailedPutResponse_RemovesTheUnpublishedObject()
    {
        _sp.GetRequiredService<IOptions<CistaNasOptions>>().Value.Storage.Provider = "s3";
        string volume = await MountE2eeAsync("put-response-cleanup");
        var storage = _sp.GetRequiredService<IStorageProvider>();
        var chunks = new TransientCleanupStore(_sp.GetRequiredService<IChunkStore>()) { FailNextWriteResponse = true };
        var service = new E2eeFileService(_volumeService, storage, chunks,
            _sp.GetRequiredService<IOptions<CistaNasOptions>>());
        var entry = await service.CreateFileAsync(volume, new E2eeCreateFileRequest("enc", 100, 1), "testuser");
        using (var content = new MemoryStream(new byte[100]))
            await Assert.ThrowsAsync<IOException>(() => service.UploadChunkAsync(volume, entry.FileId, 0, content, 100));
        Assert.Empty(await storage.ListAsync($"{volume}/chunks/{entry.FileId}/"));
        Assert.Empty(Assert.Single((await service.ListFilesAsync(volume)).Files).ChunkObjectIds);
        using (var retry = new MemoryStream(new byte[100]))
            await service.UploadChunkAsync(volume, entry.FileId, 0, retry, 100);
        Assert.Single(await storage.ListAsync($"{volume}/chunks/{entry.FileId}/"));
    }

    internal sealed class TransientCleanupStore(IChunkStore inner) : IChunkStore
    {
        public bool FailNextDelete { get; set; }
        public bool FailNextWriteResponse { get; set; }
        public int DeleteAttempts { get; private set; }
        public Task DeleteChunksAsync(string v, string id, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            DeleteAttempts++;
            if (FailNextDelete)
            {
                FailNextDelete = false;
                throw new IOException("temporary object deletion failure");
            }
            return inner.DeleteChunksAsync(v, id, ct);
        }
        public async Task WriteChunkAsync(string v, string id, int index, Stream data, CancellationToken ct = default)
        {
            await inner.WriteChunkAsync(v, id, index, data, ct);
            if (FailNextWriteResponse)
            {
                FailNextWriteResponse = false;
                throw new IOException("object accepted but response failed");
            }
        }
        public Task<byte[]?> ReadChunkAsync(string v, string id, int index, CancellationToken ct = default) => inner.ReadChunkAsync(v, id, index, ct);
        public byte[]? ReadChunk(string v, string id, int index) => inner.ReadChunk(v, id, index);
        public Task<IReadOnlyList<int>> ListChunksAsync(string v, string id, CancellationToken ct = default) => inner.ListChunksAsync(v, id, ct);
        public Task DeleteVolumeChunksAsync(string v, CancellationToken ct = default) => inner.DeleteVolumeChunksAsync(v, ct);
    }

    internal sealed class CancelAfterCatalogStorage(IStorageProvider inner, CancellationTokenSource cancellation) : IStorageProvider
    {
        public bool CancelAfterSave { get; set; }
        public async Task WriteAtomicAsync(string path, Stream data, CancellationToken ct = default)
        {
            await inner.WriteAtomicAsync(path, data, ct);
            if (CancelAfterSave && (path.EndsWith("/catalog-e2ee.json", StringComparison.Ordinal)
                || path.EndsWith("/catalog.json", StringComparison.Ordinal))) cancellation.Cancel();
        }
        public Task<byte[]?> ReadAsync(string path, CancellationToken ct = default) => inner.ReadAsync(path, ct);
        public Task WriteAsync(string path, Stream data, CancellationToken ct = default) => inner.WriteAsync(path, data, ct);
        public Task DeleteAsync(string path, CancellationToken ct = default) => inner.DeleteAsync(path, ct);
        public Task<bool> ExistsAsync(string path, CancellationToken ct = default) => inner.ExistsAsync(path, ct);
        public Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default) => inner.ListAsync(prefix, ct);
        public Task<IDisposable> AcquireLockAsync(string path, CancellationToken ct = default) => inner.AcquireLockAsync(path, ct);
        public void RemoveLock(string path) => inner.RemoveLock(path);
    }
}
