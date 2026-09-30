using CistaNAS.Web.Configuration;
using CistaNAS.Web.Journal;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;

namespace CistaNAS.Tests;

public sealed class FileServiceIntegrityTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task PatchBeyondEof_ZeroFillsGap_AndPreservesNeighbor(bool chunked, bool encrypted)
    {
        await using var fixture = await Fixture.CreateAsync(chunked, encrypted);
        byte[] original = Enumerable.Repeat((byte)0x41, 100).ToArray();
        byte[] secret = Enumerable.Repeat((byte)0xD7, 12000).ToArray();
        await fixture.UploadAsync("public.bin", original);
        await fixture.UploadAsync("private.bin", secret);

        byte[] patch = [1, 2, 3];
        await fixture.Files.PatchRangeAsync(fixture.Volume, "public.bin", 9000,
            new MemoryStream(patch), patch.Length);

        byte[] expected = new byte[9003];
        original.CopyTo(expected, 0);
        patch.CopyTo(expected, 9000);
        Assert.Equal(expected, await fixture.ReadAsync("public.bin"));
        Assert.Equal(secret, await fixture.ReadAsync("private.bin"));
        await fixture.RemountAsync();
        Assert.Equal(expected, await fixture.ReadAsync("public.bin"));
        Assert.Equal(secret, await fixture.ReadAsync("private.bin"));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task IncompleteOverwrite_IsRejected_AndPreservesOriginal(bool chunked, bool encrypted)
    {
        await using var fixture = await Fixture.CreateAsync(chunked, encrypted);
        byte[] original = Enumerable.Repeat((byte)0xA5, 20000).ToArray();
        await fixture.UploadAsync("keep.bin", original);
        byte[] catalog = (await fixture.Storage.ReadAsync($"{fixture.Volume}/catalog.json"))!;

        await Assert.ThrowsAsync<FileServiceException>(() => fixture.Files.UploadAsync(
            fixture.Volume, "keep.bin", new MemoryStream(new byte[10000]), 15000));

        Assert.Equal(catalog, await fixture.Storage.ReadAsync($"{fixture.Volume}/catalog.json"));
        Assert.Equal(original, await fixture.ReadAsync("keep.bin"));
        await fixture.RemountAsync();
        Assert.Equal(original, await fixture.ReadAsync("keep.bin"));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task IncompletePatch_IsRejected_AndPreservesOriginal(bool chunked, bool encrypted)
    {
        await using var fixture = await Fixture.CreateAsync(chunked, encrypted);
        byte[] original = Enumerable.Repeat((byte)0xA5, 20000).ToArray();
        await fixture.UploadAsync("keep.bin", original);
        await Assert.ThrowsAsync<FileServiceException>(() => fixture.Files.PatchRangeAsync(
            fixture.Volume, "keep.bin", 20, new MemoryStream(new byte[100]), 200));
        Assert.Equal(original, await fixture.ReadAsync("keep.bin"));
        await fixture.RemountAsync();
        Assert.Equal(original, await fixture.ReadAsync("keep.bin"));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task InterruptedWrite_PreservesOriginal(bool patch, bool encrypted)
    {
        await using var fixture = await Fixture.CreateAsync(false, encrypted);
        byte[] original = Enumerable.Repeat((byte)0xB6, 20000).ToArray();
        await fixture.UploadAsync("keep.bin", original);
        using var interrupted = new InterruptedStream(new byte[10000]);
        await Assert.ThrowsAsync<IOException>(() => patch
            ? fixture.Files.PatchRangeAsync(fixture.Volume, "keep.bin", 30, interrupted, 10000)
            : fixture.Files.UploadAsync(fixture.Volume, "keep.bin", interrupted, 10000));
        Assert.Equal(original, await fixture.ReadAsync("keep.bin"));
        await fixture.RemountAsync();
        Assert.Equal(original, await fixture.ReadAsync("keep.bin"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CatalogSaveFailure_PreservesOriginal(bool patch)
    {
        await using var fixture = await Fixture.CreateAsync(false, true);
        byte[] original = Enumerable.Repeat((byte)0xB6, 20000).ToArray();
        await fixture.UploadAsync("keep.bin", original);
        fixture.Storage.FailCatalogWrites = true;
        using var content = new MemoryStream(new byte[10000]);
        await Assert.ThrowsAsync<IOException>(() => patch
            ? fixture.Files.PatchRangeAsync(fixture.Volume, "keep.bin", 30, content, 10000)
            : fixture.Files.UploadAsync(fixture.Volume, "keep.bin", content, 10000));
        fixture.Storage.FailCatalogWrites = false;
        Assert.Equal(original, await fixture.ReadAsync("keep.bin"));
        await fixture.RemountAsync();
        Assert.Equal(original, await fixture.ReadAsync("keep.bin"));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task CanceledWrite_PreservesOriginal(bool patch, bool encrypted)
    {
        await using var fixture = await Fixture.CreateAsync(false, encrypted);
        byte[] original = Enumerable.Repeat((byte)0xB6, 20000).ToArray();
        await fixture.UploadAsync("keep.bin", original);
        using var cancellation = new CancellationTokenSource();
        using var content = new CancelAfterReadStream(new byte[10000], cancellation);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => patch
            ? fixture.Files.PatchRangeAsync(fixture.Volume, "keep.bin", 30, content, 10000, cancellation.Token)
            : fixture.Files.UploadAsync(fixture.Volume, "keep.bin", content, 10000, cancellation.Token));
        Assert.Equal(original, await fixture.ReadAsync("keep.bin"));
        await fixture.RemountAsync();
        Assert.Equal(original, await fixture.ReadAsync("keep.bin"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FragmentedUpload_UsesFullSizedChunks_AndSupportsSparsePatch(bool encrypted)
    {
        await using var fixture = await Fixture.CreateAsync(true, encrypted);
        byte[] original = Enumerable.Range(0, 9000).Select(i => (byte)(i % 251)).ToArray();
        using var fragmented = new FragmentedStream(original);
        var meta = await fixture.Files.UploadAsync(fixture.Volume, "fragments.bin", fragmented, original.Length);
        Assert.Equal(new[] { 4096, 4096, 808 }, meta.ChunkSizes);
        await fixture.Files.PatchRangeAsync(fixture.Volume, "fragments.bin", 15000,
            new MemoryStream(new byte[] { 42 }), 1);
        byte[] expected = new byte[15001];
        original.CopyTo(expected, 0);
        expected[15000] = 42;
        Assert.Equal(expected, await fixture.ReadAsync("fragments.bin"));
    }

    [Fact]
    public async Task Recovery_TransientListingFailure_PreservesCatalogAndJournal()
    {
        await using var fixture = await Fixture.CreateAsync(true, false);
        byte[] original = [1, 2, 3];
        await fixture.UploadAsync("keep.bin", original);
        var journal = new JournalService(fixture.Storage);
        await journal.RecordAsync(fixture.Volume, new JournalEntry { Operation = JournalOp.WriteFile, Path = "unfinished.bin" });
        byte[] catalog = (await fixture.Storage.ReadAsync($"{fixture.Volume}/catalog.json"))!;
        fixture.Storage.FailChunkListing = true;
        await Assert.ThrowsAsync<IOException>(() => fixture.Files.RecoverAsync(fixture.Volume));
        fixture.Storage.FailChunkListing = false;
        Assert.Equal(catalog, await fixture.Storage.ReadAsync($"{fixture.Volume}/catalog.json"));
        Assert.True(await journal.HasPendingAsync(fixture.Volume));
        await fixture.Files.RecoverAsync(fixture.Volume);
        Assert.Equal(original, await fixture.ReadAsync("keep.bin"));
        Assert.False(await journal.HasPendingAsync(fixture.Volume));
    }

    [Fact]
    public async Task Delete_WithQueuedDownload_CompletesAndAllowsRecreation()
    {
        await using var fixture = await Fixture.CreateAsync(false, false);
        await fixture.UploadAsync("victim.bin", new byte[] { 1, 2, 3 });
        var catalogSaved = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finishDelete = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Storage.AfterCatalogWrite = async () =>
        {
            catalogSaved.SetResult();
            await finishDelete.Task;
        };

        Task deletion = fixture.Files.DeleteAsync(fixture.Volume, "victim.bin");
        try
        {
            await catalogSaved.Task.WaitAsync(TimeSpan.FromSeconds(5));
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var download = fixture.Files.DownloadAsync(fixture.Volume, "victim.bin", timeout.Token);
            Assert.False(download.IsCompleted);
            finishDelete.SetResult();
            await deletion.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.ThrowsAsync<FileServiceException>(() => download.WaitAsync(TimeSpan.FromSeconds(5)));
        }
        finally
        {
            finishDelete.TrySetResult();
            fixture.Storage.AfterCatalogWrite = null;
            await deletion.WaitAsync(TimeSpan.FromSeconds(5));
        }

        byte[] recreated = [4, 5, 6];
        await fixture.UploadAsync("victim.bin", recreated);
        Assert.Equal(recreated, await fixture.ReadAsync("victim.bin"));
    }

    private sealed class InterruptedStream(byte[] data) : MemoryStream(data)
    {
        private bool _read;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_read) throw new IOException("Simulated disconnection");
            _read = true;
            return base.ReadAsync(buffer[..Math.Min(buffer.Length, 100)], cancellationToken);
        }
    }

    private sealed class FragmentedStream(byte[] data) : MemoryStream(data)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => base.ReadAsync(buffer[..Math.Min(buffer.Length, 137)], cancellationToken);
    }

    private sealed class CancelAfterReadStream(byte[] data, CancellationTokenSource cancellation) : MemoryStream(data)
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int read = await base.ReadAsync(buffer[..Math.Min(buffer.Length, 100)], cancellationToken);
            cancellation.Cancel();
            return read;
        }
    }

    private sealed class FaultStorage(IStorageProvider inner) : IStorageProvider
    {
        public bool FailCatalogWrites { get; set; }
        public bool FailChunkListing { get; set; }
        public Func<Task>? AfterCatalogWrite { get; set; }
        public Task<byte[]?> ReadAsync(string path, CancellationToken ct = default) => inner.ReadAsync(path, ct);
        public Task WriteAsync(string path, Stream content, CancellationToken ct = default) => inner.WriteAsync(path, content, ct);
        public async Task WriteAtomicAsync(string path, Stream content, CancellationToken ct = default)
        {
            if (FailCatalogWrites && path.EndsWith("/catalog.json"))
                throw new IOException("Simulated catalog save failure");
            await inner.WriteAtomicAsync(path, content, ct);
            if (path.EndsWith("/catalog.json") && AfterCatalogWrite is { } afterWrite)
                await afterWrite();
        }
        public Task DeleteAsync(string path, CancellationToken ct = default) => inner.DeleteAsync(path, ct);
        public Task<bool> ExistsAsync(string path, CancellationToken ct = default) => inner.ExistsAsync(path, ct);
        public Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default)
            => FailChunkListing && prefix?.Contains("/chunks/") == true
                ? Task.FromException<IReadOnlyList<string>>(new IOException("Simulated storage outage"))
                : inner.ListAsync(prefix, ct);
        public Task<IDisposable> AcquireLockAsync(string path, CancellationToken ct = default) => inner.AcquireLockAsync(path, ct);
        public void RemoveLock(string path) => inner.RemoveLock(path);
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly IServiceProvider _services;
        private readonly string _root;
        private readonly VolumeService _volumes;
        public string Volume { get; } = "integrity-" + Guid.NewGuid().ToString("N");
        public FileService Files { get; }
        public FaultStorage Storage { get; }

        private Fixture(bool chunked)
        {
            (_services, _root) = TestHelper.BuildTestServices(new VolumeOptions
            {
                ChunkStorage = chunked ? "auto" : "local", ServerChunkSize = 4096, SectorSize = 512,
                KdfIterations = 10000, KdfMemoryKiB = 8192, KdfTimeCost = 1, KdfParallelism = 1,
            }, new StorageOptions { Provider = chunked ? "s3" : "local" });
            _volumes = _services.GetRequiredService<VolumeService>();
            Storage = new FaultStorage(_services.GetRequiredService<IStorageProvider>());
            Files = new FileService(_volumes, new JournalService(Storage), Storage, new S3ChunkStore(Storage));
        }

        public static async Task<Fixture> CreateAsync(bool chunked, bool encrypted)
        {
            var fixture = new Fixture(chunked);
            await fixture._volumes.CreateAsync(fixture.Volume, "testuser", "testpw", encrypted);
            return fixture;
        }

        public Task UploadAsync(string name, byte[] data)
            => Files.UploadAsync(Volume, name, new MemoryStream(data), data.Length);
        public async Task<byte[]> ReadAsync(string name)
        {
            var response = await Files.DownloadAsync(Volume, name);
            await using var stream = response.Stream;
            using var result = new MemoryStream();
            await stream.CopyToAsync(result);
            return result.ToArray();
        }
        public async Task RemountAsync()
        {
            await _volumes.LockAsync(Volume, "testuser");
            await _volumes.MountAsync(Volume, "testuser", "testpw");
        }
        public async ValueTask DisposeAsync()
        {
            await _volumes.LockAsync(Volume, "testuser");
            if (_services is IAsyncDisposable disposable) await disposable.DisposeAsync();
            Directory.Delete(_root, recursive: true);
        }
    }
}
