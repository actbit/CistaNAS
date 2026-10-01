using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public partial class E2eeFileTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ListingDuringDeletion_DoesNotCancelQueuedDownloads(bool chunkMode)
    {
        _sp.GetRequiredService<IOptions<CistaNasOptions>>().Value.Storage.Provider = chunkMode ? "s3" : "local";
        string volume = await MountE2eeAsync("delete-list-" + Guid.NewGuid().ToString("N"));
        var storage = new PausedCatalogStorage(_sp.GetRequiredService<IStorageProvider>());
        var service = new E2eeFileService(_volumeService, storage, _sp.GetRequiredService<IChunkStore>(),
            _sp.GetRequiredService<IOptions<CistaNasOptions>>());
        var entry = await service.CreateFileAsync(volume, new E2eeCreateFileRequest("enc", 100, 1), "testuser");
        using (var bytes = new MemoryStream(new byte[100]))
            await service.UploadChunkAsync(volume, entry.FileId, 0, bytes, 100);
        storage.Pause = true;
        Task deletion = service.DeleteFileAsync(volume, entry.FileId);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            await storage.Saved.Task.WaitAsync(timeout.Token);
            Task<(Stream Stream, long Length, int Revision, int KeyEpoch)> download =
                service.DownloadChunkAsync(volume, entry.FileId, 0, timeout.Token);
            Assert.False(download.IsCompleted);
            Assert.Empty((await service.ListFilesAsync(volume, timeout.Token)).Files);
            storage.Release.TrySetResult();
            await deletion.WaitAsync(timeout.Token);
            await Assert.ThrowsAsync<FileServiceException>(() => download.WaitAsync(timeout.Token));
        }
        finally { storage.Release.TrySetResult(); await deletion.WaitAsync(timeout.Token); }
    }

    [Fact]
    public async Task RecreatingFileIdDuringChunkDeletion_PreservesTheNewFile()
    {
        _sp.GetRequiredService<IOptions<CistaNasOptions>>().Value.Storage.Provider = "s3";
        string volume = await MountE2eeAsync("delete-recreate-" + Guid.NewGuid().ToString("N"));
        var chunks = new PausedDeletionStore(_sp.GetRequiredService<IChunkStore>());
        var service = new E2eeFileService(_volumeService, _sp.GetRequiredService<IStorageProvider>(), chunks,
            _sp.GetRequiredService<IOptions<CistaNasOptions>>());
        var entry = await service.CreateFileAsync(volume, new E2eeCreateFileRequest("old", 100, 1), "testuser");
        using (var old = new MemoryStream(new byte[100]))
            await service.UploadChunkAsync(volume, entry.FileId, 0, old, 100);
        chunks.Pause = true;
        Task deletion = service.DeleteFileAsync(volume, entry.FileId);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        Task? recreation = null;
        byte[] expected = Enumerable.Repeat((byte)42, 100).ToArray();
        try
        {
            await chunks.Entered.Task.WaitAsync(timeout.Token);
            recreation = RecreateAsync();
            // Give the old implementation a chance to finish its incorrectly
            // concurrent creation/upload before the pending prefix deletion.
            await Task.WhenAny(recreation, Task.Delay(250, timeout.Token));
            chunks.Release.TrySetResult();
            await deletion.WaitAsync(timeout.Token);
            await recreation.WaitAsync(timeout.Token);
            var (stream, _, _, _) = await service.DownloadChunkAsync(volume, entry.FileId, 0, timeout.Token);
            using (stream)
            {
                byte[] actual = new byte[expected.Length];
                await stream.ReadExactlyAsync(actual, timeout.Token);
                Assert.Equal(expected, actual);
            }
        }
        finally
        {
            chunks.Release.TrySetResult();
            await deletion.WaitAsync(timeout.Token);
            if (recreation is not null) await recreation.WaitAsync(timeout.Token);
        }

        async Task RecreateAsync()
        {
            await service.CreateFileAsync(volume, new E2eeCreateFileRequest("new", 100, 1), "testuser",
                timeout.Token, preallocatedFileId: entry.FileId);
            using var content = new MemoryStream(expected);
            await service.UploadChunkAsync(volume, entry.FileId, 0, content, expected.Length, ct: timeout.Token);
        }
    }

    private sealed class PausedCatalogStorage(IStorageProvider inner) : IStorageProvider
    {
        public bool Pause { get; set; }
        public TaskCompletionSource Saved { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task WriteAtomicAsync(string path, Stream content, CancellationToken ct = default)
        {
            await inner.WriteAtomicAsync(path, content, ct);
            if (Pause && path.EndsWith("/catalog-e2ee.json", StringComparison.Ordinal))
            { Saved.TrySetResult(); await Release.Task.WaitAsync(ct); }
        }
        public Task<byte[]?> ReadAsync(string path, CancellationToken ct = default) => inner.ReadAsync(path, ct);
        public Task WriteAsync(string path, Stream content, CancellationToken ct = default) => inner.WriteAsync(path, content, ct);
        public Task DeleteAsync(string path, CancellationToken ct = default) => inner.DeleteAsync(path, ct);
        public Task<bool> ExistsAsync(string path, CancellationToken ct = default) => inner.ExistsAsync(path, ct);
        public Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default) => inner.ListAsync(prefix, ct);
        public Task<IDisposable> AcquireLockAsync(string path, CancellationToken ct = default) => inner.AcquireLockAsync(path, ct);
        public void RemoveLock(string path) => inner.RemoveLock(path);
    }

    private sealed class PausedDeletionStore(IChunkStore inner) : IChunkStore
    {
        public bool Pause { get; set; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task DeleteChunksAsync(string volumeName, string objectId, CancellationToken ct = default)
        {
            if (Pause) { Entered.TrySetResult(); await Release.Task.WaitAsync(ct); }
            await inner.DeleteChunksAsync(volumeName, objectId, ct);
        }
        public Task WriteChunkAsync(string v, string id, int index, Stream data, CancellationToken ct = default) => inner.WriteChunkAsync(v, id, index, data, ct);
        public Task<byte[]?> ReadChunkAsync(string v, string id, int index, CancellationToken ct = default) => inner.ReadChunkAsync(v, id, index, ct);
        public byte[]? ReadChunk(string v, string id, int index) => inner.ReadChunk(v, id, index);
        public Task<IReadOnlyList<int>> ListChunksAsync(string v, string id, CancellationToken ct = default) => inner.ListChunksAsync(v, id, ct);
        public Task DeleteVolumeChunksAsync(string v, CancellationToken ct = default) => inner.DeleteVolumeChunksAsync(v, ct);
    }
}
