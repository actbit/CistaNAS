using System.Text.Json;
using CistaNAS.Web.Storage;

namespace CistaNAS.Tests;

public sealed class CatalogStorageTests
{
    [Fact]
    public async Task InitializeEmptyAsync_CompletesStorageWriteBeforeDisposingStream()
    {
        var provider = new DeferredWriteStorageProvider();

        await CatalogStorage.InitializeEmptyAsync(provider, "volume", e2ee: false);

        Assert.NotNull(provider.Payload);
        using var document = JsonDocument.Parse(provider.Payload!);
        Assert.True(document.RootElement.TryGetProperty("Files", out var files));
        Assert.Equal(JsonValueKind.Object, files.ValueKind);
        Assert.Empty(files.EnumerateObject());
    }

    private sealed class DeferredWriteStorageProvider : IStorageProvider
    {
        public byte[]? Payload { get; private set; }

        public string RecoveryIdentity => "catalog-test";

        public Task<byte[]?> ReadAsync(string blobPath, CancellationToken ct = default)
            => Task.FromResult<byte[]?>(null);

        public Task WriteAsync(string blobPath, Stream content, CancellationToken ct = default)
            => WriteAtomicAsync(blobPath, content, ct);

        public async Task WriteAtomicAsync(string blobPath, Stream content, CancellationToken ct = default)
        {
            await Task.Yield();
            using var copy = new MemoryStream();
            await content.CopyToAsync(copy, ct);
            Payload = copy.ToArray();
        }

        public Task DeleteAsync(string blobPath, CancellationToken ct = default)
            => Task.CompletedTask;

        public Task<bool> ExistsAsync(string blobPath, CancellationToken ct = default)
            => Task.FromResult(false);

        public Task<IReadOnlyList<string>> ListAsync(string? prefix = null, CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<string>>([]);

        public Task<IDisposable> AcquireLockAsync(string lockPath, CancellationToken ct = default)
            => Task.FromResult<IDisposable>(new NoopDisposable());

        public void RemoveLock(string lockPath) { }

        private sealed class NoopDisposable : IDisposable
        {
            public void Dispose() { }
        }
    }
}
