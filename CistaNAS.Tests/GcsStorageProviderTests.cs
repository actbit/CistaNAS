using System.Runtime.CompilerServices;
using Google.Api.Gax;
using Google.Cloud.Storage.V1;
using Google.Apis.Storage.v1.Data;
using CistaNAS.Web.Storage;
using StorageObject = Google.Apis.Storage.v1.Data.Object;

namespace CistaNAS.Tests;

public sealed class GcsStorageProviderTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task ListRoot_ContainsOnlyConfiguredInstanceObjects(string? prefix)
    {
        var client = new ListingClient("instance-a/vol/header.json", "instance-b/private/header.json");
        await using var storage = new GcsStorageProvider(client, "shared-bucket", "instance-a/");
        var files = await storage.ListAsync(prefix);
        Assert.Equal(new[] { "vol/header.json" }, files);
    }

    [Fact]
    public async Task ListChild_StripsOnlyConfiguredInstancePrefix()
    {
        var client = new ListingClient("instance-a/vol/header.json", "instance-a/other/header.json",
            "instance-b/vol/header.json");
        await using var storage = new GcsStorageProvider(client, "shared-bucket", "instance-a");
        Assert.Equal(new[] { "vol/header.json" }, await storage.ListAsync("vol/"));
    }

    [Fact]
    public async Task ListRoot_CancellationStopsEnumeration()
    {
        var client = new ListingClient("instance-a/vol/header.json");
        await using var storage = new GcsStorageProvider(client, "shared-bucket", "instance-a/");
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => storage.ListAsync(null, cts.Token));
    }

    private sealed class ListingClient(params string[] names) : StorageClient
    {
        public override PagedAsyncEnumerable<Objects, StorageObject> ListObjectsAsync(string bucket,
            string? prefix = null, ListObjectsOptions? options = null)
            => new Pages(names.Where(n => prefix is null || n.StartsWith(prefix, StringComparison.Ordinal))
                .Select(n => new StorageObject { Name = n }).ToArray());
    }

    private sealed class Pages(StorageObject[] objects) : PagedAsyncEnumerable<Objects, StorageObject>
    {
        public override IAsyncEnumerator<StorageObject> GetAsyncEnumerator(CancellationToken ct = default)
            => Enumerate(ct).GetAsyncEnumerator(ct);
        private async IAsyncEnumerable<StorageObject> Enumerate([EnumeratorCancellation] CancellationToken ct)
        {
            await Task.CompletedTask;
            foreach (var item in objects) { ct.ThrowIfCancellationRequested(); yield return item; }
        }
        public override IAsyncEnumerable<Objects> AsRawResponses() => throw new NotSupportedException();
        public override Task<Page<StorageObject>> ReadPageAsync(int size, CancellationToken ct = default)
            => throw new NotSupportedException();
    }
}
