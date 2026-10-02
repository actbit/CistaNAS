using CistaNAS.Web.Storage;

namespace CistaNAS.Tests;

public sealed class ChunkListingRegressionTests
{
    [Fact]
    public async Task LocalBackedListing_OnlyCountsReadableChunksOfTheRequestedObject()
    {
        string root = Path.Combine(Path.GetTempPath(), "cista-chunk-list-" + Guid.NewGuid().ToString("N"));
        try { await VerifyListingAsync(new LocalStorageProvider(root)); }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    internal static async Task VerifyListingAsync(IStorageProvider storage)
    {
        var store = new S3ChunkStore(storage);
        string volume = "listing-" + Guid.NewGuid().ToString("N");
        try
        {
            await store.WriteChunkAsync(volume, "file", 1, new MemoryStream(new byte[] { 1 }));
            await store.WriteChunkAsync(volume, "file", 100_000, new MemoryStream(new byte[] { 2 }));
            foreach (string suffix in new[] { "versions/new/00000", "child/00002", "1", "000000", "-00001", "00003.tmp" })
                await storage.WriteAsync($"{volume}/chunks/file/{suffix}", new MemoryStream(new byte[] { 99 }));

            Assert.Equal(new[] { 1, 100_000 }, await store.ListChunksAsync(volume, "file"));
            Assert.Null(await store.ReadChunkAsync(volume, "file", 0));
            Assert.Null(await store.ReadChunkAsync(volume, "file", 2));
            Assert.Equal(new byte[] { 1 }, await store.ReadChunkAsync(volume, "file", 1));
            Assert.Equal(new byte[] { 2 }, await store.ReadChunkAsync(volume, "file", 100_000));
        }
        finally { await store.DeleteVolumeChunksAsync(volume); }
    }
}
