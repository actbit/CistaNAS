using CistaNAS.Shared.Crypto;
using CistaNAS.Tests.Helpers;
using CistaNAS.Web.Services;
using CistaNAS.Web.Services.Streams;
using CistaNAS.Web.Storage;

namespace CistaNAS.Tests;

public sealed class StorageReadFailureRegressionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShortStoredChunk_ThrowsInsteadOfSpinningUntilCancellation(bool encrypted)
    {
        var store = new InMemoryChunkStore();
        byte[] key = new byte[32];
        byte[] data = encrypted
            ? ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.ChaCha20, 0, 512, 4096, new byte[17])
            : [1, 2, 3];
        await store.WriteChunkAsync("vol", "file", 0, new MemoryStream(data));
        using Stream stream = encrypted
            ? new ChunkedReadStream(store, "vol", "file", key, CipherAlgorithm.ChaCha20, 512, 4096, [33])
            : new MemoryChunkedStream(store, "vol", "file", [4]);
        using var stop = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
        await Assert.ThrowsAsync<InvalidDataException>(() => stream.ReadAsync(new byte[encrypted ? 33 : 4], stop.Token).AsTask());
    }

    [Fact]
    public async Task OverlongStoredChunk_CannotLeakIntoNextLogicalChunk()
    {
        var store = new InMemoryChunkStore();
        await store.WriteChunkAsync("vol", "file", 0, new MemoryStream(new byte[] { 1, 2, 3, 4, 99, 99 }));
        await store.WriteChunkAsync("vol", "file", 1, new MemoryStream(new byte[] { 5, 6, 7, 8 }));
        using var stream = new MemoryChunkedStream(store, "vol", "file", [4, 4]);
        await Assert.ThrowsAsync<InvalidDataException>(() => stream.ReadAsync(new byte[8]).AsTask());
    }

    [Fact]
    public async Task DisposingGate_CancelsQueuedReaders_AndAllowsHeldWriterToExit()
    {
        var gate = new AsyncFileGate();
        var writer = await gate.EnterWriteAsync(default);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        Task<IDisposable> queued = gate.EnterReadAsync(stop.Token);
        gate.Dispose();
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queued.WaitAsync(TimeSpan.FromSeconds(1)));
            writer.Dispose();
        }
        finally { stop.Cancel(); }
    }

    [Fact]
    public async Task TransientChunkDeletion_IsActuallyRetried()
    {
        var storage = new DeleteFailureStorage();
        var store = new S3ChunkStore(storage);
        await store.DeleteChunksWithRetryAsync("vol", "file", default);
        Assert.Empty(storage.Keys);
        Assert.Equal(2, storage.Attempts);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ChunkDeletion_DoesNotSwallowCancellation(bool wholeVolume)
    {
        var storage = new DeleteFailureStorage { Cancel = true };
        var store = new S3ChunkStore(storage);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => wholeVolume
            ? store.DeleteVolumeChunksAsync("vol") : store.DeleteChunksAsync("vol", "file"));
    }

    private sealed class DeleteFailureStorage : IStorageProvider
    {
        public List<string> Keys { get; } = ["vol/chunks/file/00000"];
        public int Attempts { get; private set; }
        public bool Cancel { get; init; }
        public Task DeleteAsync(string path, CancellationToken ct = default)
        {
            Attempts++;
            if (Cancel) throw new OperationCanceledException();
            if (Attempts == 1) throw new IOException("Transient delete failure");
            Keys.Remove(path);
            return Task.CompletedTask;
        }
        public Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<string>>([.. Keys]);
        public Task<byte[]?> ReadAsync(string path, CancellationToken ct = default) => throw new NotSupportedException();
        public Task WriteAsync(string path, Stream content, CancellationToken ct = default) => throw new NotSupportedException();
        public Task WriteAtomicAsync(string path, Stream content, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<bool> ExistsAsync(string path, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IDisposable> AcquireLockAsync(string path, CancellationToken ct = default) => throw new NotSupportedException();
        public void RemoveLock(string path) { }
    }
}
