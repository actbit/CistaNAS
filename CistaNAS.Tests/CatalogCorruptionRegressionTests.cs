using System.Text;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;

namespace CistaNAS.Tests;

public sealed class CatalogCorruptionRegressionTests : IAsyncDisposable
{
    private readonly IServiceProvider _services;
    private readonly string _dataRoot;

    public CatalogCorruptionRegressionTests()
        => (_services, _dataRoot) = TestHelper.BuildTestServices();

    [Theory]
    [InlineData(false, "null")]
    [InlineData(false, "{}")]
    [InlineData(false, "{\"Files\":null}")]
    [InlineData(false, "{\"Files\":{\"lost\":null}}")]
    [InlineData(true, "null")]
    [InlineData(true, "{}")]
    [InlineData(true, "{\"Files\":null}")]
    [InlineData(true, "{\"Files\":{\"lost\":null}}")]
    public async Task InvalidCatalog_BlocksWritesAndPreservesStoredData(bool e2ee, string invalidJson)
    {
        string volume = "catalog-" + Guid.NewGuid().ToString("N");
        var volumes = _services.GetRequiredService<VolumeService>();
        var storage = _services.GetRequiredService<IStorageProvider>();
        using var scope = _services.CreateScope();
        var files = scope.ServiceProvider.GetRequiredService<FileService>();
        var encryptedFiles = scope.ServiceProvider.GetRequiredService<E2eeFileService>();
        if (e2ee)
        {
            byte[] salt = E2eeCrypto.GenerateFileSalt();
            byte[] kek = E2eeCrypto.DeriveKek("owner", "password", salt, 1000);
            var (nonce, ciphertext, tag) = E2eeCrypto.WrapMasterKey(new byte[32], kek);
            await volumes.CreateE2eeAsync(volume, "owner", new VolumeHeader.UserWrappedKey
            {
                Kdf = new() { Algorithm = "pbkdf2-sha256", Iterations = 1000, Salt = salt },
                WrappedMasterKey = new() { Algorithm = "aes-256-gcm", Nonce = nonce, Ciphertext = ciphertext, Tag = tag }
            });
            await encryptedFiles.CreateFileAsync(volume, new E2eeCreateFileRequest("original", 33, 1), "owner");
        }
        else
        {
            await volumes.CreateAsync(volume, "owner", "password", encrypted: false);
            await files.UploadAsync(volume, "original", new MemoryStream(new byte[] { 1, 2, 3 }), 3);
        }

        string catalogPath = $"{volume}/catalog{(e2ee ? "-e2ee" : "")}.json";
        byte[] originalCatalog = (await storage.ReadAsync(catalogPath))!;
        byte[] corruptCatalog = Encoding.UTF8.GetBytes(invalidJson);
        await storage.WriteAtomicAsync(catalogPath, new MemoryStream(corruptCatalog));

        if (e2ee)
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => encryptedFiles.ListFilesAsync(volume));
            await Assert.ThrowsAsync<InvalidDataException>(() => encryptedFiles.CreateFileAsync(
                volume, new E2eeCreateFileRequest("new", 33, 1), "owner"));
        }
        else
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => files.ListAsync(volume));
            await Assert.ThrowsAsync<InvalidDataException>(() => files.UploadAsync(
                volume, "new", new MemoryStream(new byte[] { 9, 9, 9 }), 3));
        }
        Assert.Equal(corruptCatalog, await storage.ReadAsync(catalogPath));

        await storage.WriteAtomicAsync(catalogPath, new MemoryStream(originalCatalog));
        if (e2ee) Assert.Single((await encryptedFiles.ListFilesAsync(volume)).Files);
        else
        {
            Assert.Single((await files.ListAsync(volume)).Files);
            var download = await files.DownloadAsync(volume, "original");
            using (download.Stream)
            {
                byte[] data = new byte[3];
                await download.Stream.ReadExactlyAsync(data);
                Assert.Equal(new byte[] { 1, 2, 3 }, data);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await ((IAsyncDisposable)_services).DisposeAsync();
        if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true);
    }
}
