using System.Net.Http.Json;
using System.Security.Cryptography;
using Amazon.S3;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Storage;

namespace CistaNAS.Tests;

public partial class MinIOStorageE2ETests
{
    [Fact]
    public async Task S3_12_ChunkListing_ExcludesOtherGenerationsAndNonCanonicalKeys()
    {
        await using var storage = CreateStorage("chunk-listing/" + Guid.NewGuid().ToString("N"));
        await ChunkListingRegressionTests.VerifyListingAsync(storage);
    }

    private S3StorageProvider CreateStorage(string? prefix = null) => new(
        MinIOFixture.Bucket, "us-east-1", fixture.MinIOEndpoint, prefix,
        new AmazonS3Client("minioadmin", "minioadmin", new AmazonS3Config
        {
            RegionEndpoint = Amazon.RegionEndpoint.USEast1,
            ServiceURL = fixture.MinIOEndpoint,
            ForcePathStyle = true,
        }));

    [Fact]
    public async Task S3_09_RepeatedPendingUpdates_KeepObjectCountBounded_AndDeleteAllGenerations()
    {
        string volume = "s3-cleanup-" + Guid.NewGuid().ToString("N");
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(MinIOFixture.Username, MinIOFixture.Password, salt, 1000);
        var (nonce, ciphertext, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        CryptographicOperations.ZeroMemory(kek);
        await Api.CreateVolumeAsync(volume, MinIOFixture.Username, nonce, ciphertext, tag, salt, 1000);
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        byte[] original = E2eeCrypto.EncryptChunk(new byte[64], fileKey, 0, fileSalt, isFirstChunk: true);
        var (fileId, lease) = await Api.CreateFileAsync(volume, "encrypted-name", original.Length, 1);
        await using var storage = CreateStorage();
        await Api.UploadChunkAsync(volume, fileId, 0, original, lease);
        for (int revision = 1; revision <= 6; revision++)
        {
            byte[] plain = Enumerable.Repeat((byte)revision, 64).ToArray();
            byte[] encrypted = E2eeCrypto.EncryptChunk(plain, fileKey, 0, fileSalt, isFirstChunk: true, revision: revision);
            await Api.UploadChunkAsync(volume, fileId, 0, encrypted, lease, replace: true);
            Assert.Equal(2, (await storage.ListAsync($"{volume}/chunks/{fileId}/versions/")).Count);
            Assert.Equal(original, (await Api.DownloadChunkAsync(volume, fileId, 0)).Data);
        }
        await Api.FinalizeFileAsync(volume, fileId, original.Length, lease, 1);
        Assert.Single(await storage.ListAsync($"{volume}/chunks/{fileId}/versions/"));
        var (latest, latestRevision, _) = await Api.DownloadChunkAsync(volume, fileId, 0);
        Assert.Equal(6, latestRevision);
        Assert.Equal(Enumerable.Repeat((byte)6, 64),
            E2eeCrypto.DecryptChunk(latest, fileKey, 0, fileSalt, revision: latestRevision));
        await Api.DeleteFileAsync(volume, fileId, lease);
        Assert.Empty(await storage.ListAsync($"{volume}/chunks/{fileId}/"));
        CryptographicOperations.ZeroMemory(fileKey);
        CryptographicOperations.ZeroMemory(masterKey);
    }

    [Fact]
    public async Task S3_10_RepeatedServerOverwrite_AndDelete_ReclaimChunks()
    {
        string volume = "s3-overwrite-cleanup-" + Guid.NewGuid().ToString("N");
        using var auth = CreateAuthClient();
        using var created = await auth.PostAsJsonAsync("/api/v1/volumes/", new
        {
            name = volume, username = MinIOFixture.Username, password = "f", encrypted = true,
        });
        created.EnsureSuccessStatusCode();
        await using var storage = CreateStorage();
        for (byte value = 0; value < 6; value++)
        {
            byte[] expected = Enumerable.Repeat(value, 128).ToArray();
            using var upload = await auth.PostAsync($"/api/v1/files/{volume}/test.bin", new ByteArrayContent(expected));
            upload.EnsureSuccessStatusCode();
            Assert.Single(await storage.ListAsync($"{volume}/chunks/"));
            using var download = await auth.GetAsync($"/api/v1/files/{volume}/test.bin");
            download.EnsureSuccessStatusCode();
            Assert.Equal(expected, await download.Content.ReadAsByteArrayAsync());
        }
        using var deletion = await auth.DeleteAsync($"/api/v1/files/{volume}/test.bin");
        deletion.EnsureSuccessStatusCode();
        Assert.Empty(await storage.ListAsync($"{volume}/chunks/"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task S3_11_RootListing_DoesNotIncludeOtherStorageNamespaces(string? rootPrefix)
    {
        string scope = "namespace-test/" + Guid.NewGuid().ToString("N");
        await using var first = CreateStorage(scope + "/first");
        await using var second = CreateStorage(scope + "/second");
        try
        {
            using (var data = new MemoryStream(new byte[] { 1 })) await first.WriteAsync("owned", data);
            using (var data = new MemoryStream(new byte[] { 2 })) await second.WriteAsync("foreign", data);
            Assert.Equal(new[] { "owned" }, await first.ListAsync(rootPrefix));
            await first.DeleteAsync("owned");
            Assert.Empty(await first.ListAsync(rootPrefix));
        }
        finally
        {
            await first.DeleteAsync("owned");
            await second.DeleteAsync("foreign");
        }
    }
}
