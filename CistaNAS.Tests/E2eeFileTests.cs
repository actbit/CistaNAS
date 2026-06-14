using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public class E2eeFileTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _volumeService;
    private readonly byte[] _masterKey;

    public E2eeFileTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _volumeService = _sp.GetRequiredService<VolumeService>();
        _masterKey = RandomNumberGenerator.GetBytes(32);
    }

    private E2eeFileService GetE2eeFileService()
    {
        using var scope = _sp.CreateAsyncScope();
        var opt = _sp.GetRequiredService<IOptions<CistaNasOptions>>();
        var storage = _sp.GetRequiredService<IStorageProvider>();
        var chunkStore = _sp.GetRequiredService<IChunkStore>();
        return new E2eeFileService(_volumeService, storage, chunkStore, opt);
    }

    [Fact]
    public async Task CreateFile_ReturnsEntryWithFileId()
    {
        string vol = await MountE2eeAsync("test-create");
        var e2eeFs = GetE2eeFileService();
        var entry = await e2eeFs.CreateFileAsync(vol, new E2eeCreateFileRequest("enc-name-abc", 2048, 2), "testuser");

        Assert.False(string.IsNullOrEmpty(entry.FileId));
        Assert.Equal("enc-name-abc", entry.EncryptedName);
        Assert.Equal(2048, entry.EncryptedLength);
        Assert.Equal(2, entry.ChunkCount);
    }

    [Fact]
    public async Task UploadAndDownloadChunk_Roundtrip()
    {
        string vol = await MountE2eeAsync("test-io");
        const int chunkSize = 4096;

        var e2eeFs = GetE2eeFileService();
        var entry = await e2eeFs.CreateFileAsync(vol, new E2eeCreateFileRequest("enc-file", chunkSize * 2 + 16 * 2 + 16, 2), "testuser");

        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(_masterKey, fileSalt);
        byte[] plain0 = RandomNumberGenerator.GetBytes(chunkSize);
        byte[] plain1 = RandomNumberGenerator.GetBytes(1000);

        byte[] encChunk0 = E2eeCrypto.EncryptChunk(plain0, fileKey, 0, fileSalt, isFirstChunk: true);
        byte[] encChunk1 = E2eeCrypto.EncryptChunk(plain1, fileKey, 1, fileSalt, isFirstChunk: false);

        using (var ms0 = new MemoryStream(encChunk0))
            await e2eeFs.UploadChunkAsync(vol, entry.FileId, 0, ms0, encChunk0.Length);
        using (var ms1 = new MemoryStream(encChunk1))
            await e2eeFs.UploadChunkAsync(vol, entry.FileId, 1, ms1, encChunk1.Length);

        var (stream0, len0) = await e2eeFs.DownloadChunkAsync(vol, entry.FileId, 0);
        byte[] dl0 = new byte[len0];
        using (stream0) await stream0.ReadExactlyAsync(dl0);
        Assert.Equal(encChunk0, dl0);

        var (stream1, len1) = await e2eeFs.DownloadChunkAsync(vol, entry.FileId, 1);
        byte[] dl1 = new byte[len1];
        using (stream1) await stream1.ReadExactlyAsync(dl1);
        Assert.Equal(encChunk1, dl1);

        byte[] dec0 = E2eeCrypto.DecryptChunk(dl0, fileKey, 0, out var salt0);
        Assert.Equal(fileSalt, salt0);
        Assert.Equal(plain0, dec0);

        // チャンク1の復号にはfileSaltが必要
        byte[] dec1 = E2eeCrypto.DecryptChunk(dl1, fileKey, 1, salt0);
        Assert.Equal(plain1, dec1);
    }

    [Fact]
    public async Task ListFiles_ReturnsCreatedFiles()
    {
        string vol = await MountE2eeAsync("test-list");
        var e2eeFs = GetE2eeFileService();
        await e2eeFs.CreateFileAsync(vol, new E2eeCreateFileRequest("enc-a", 100, 1), "testuser");
        await e2eeFs.CreateFileAsync(vol, new E2eeCreateFileRequest("enc-b", 200, 1), "testuser");

        var result = await e2eeFs.ListFilesAsync(vol);
        Assert.Equal(2, result.Files.Count);
        Assert.Contains(result.Files, f => f.EncryptedName == "enc-a");
        Assert.Contains(result.Files, f => f.EncryptedName == "enc-b");
    }

    [Fact]
    public async Task DeleteFile_RemovesFromCatalog()
    {
        string vol = await MountE2eeAsync("test-delete");
        var e2eeFs = GetE2eeFileService();
        var entry = await e2eeFs.CreateFileAsync(vol, new E2eeCreateFileRequest("to-delete", 100, 1), "testuser");

        Assert.Single((await e2eeFs.ListFilesAsync(vol)).Files);
        await e2eeFs.DeleteFileAsync(vol, entry.FileId);
        Assert.Empty((await e2eeFs.ListFilesAsync(vol)).Files);
    }

    [Fact]
    public async Task FinalizeFile_UpdatesLength()
    {
        string vol = await MountE2eeAsync("test-finalize");
        var e2eeFs = GetE2eeFileService();
        var entry = await e2eeFs.CreateFileAsync(vol, new E2eeCreateFileRequest("enc", 2048, 2), "testuser");

        await e2eeFs.FinalizeFileAsync(vol, entry.FileId, new E2eeFinalizeFileRequest(1500));

        var list = await e2eeFs.ListFilesAsync(vol);
        Assert.Single(list.Files);
        Assert.Equal(1500, list.Files[0].EncryptedLength);
    }

    [Fact]
    public async Task DeleteFile_NonExistent_Throws()
    {
        string vol = await MountE2eeAsync("test-del-missing");
        var e2eeFs = GetE2eeFileService();
        await Assert.ThrowsAsync<FileServiceException>(() =>
            e2eeFs.DeleteFileAsync(vol, "nonexistent-id"));
    }

    private async Task<string> MountE2eeAsync(string name)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek("testuser", "testpass", salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(_masterKey, kek);

        await _volumeService.CreateE2eeAsync(name, "testuser", new VolumeHeader.UserWrappedKey
        {
            Kdf = new() { Algorithm = "pbkdf2-sha256", Iterations = 1000, Salt = salt },
            WrappedMasterKey = new()
            {
                Algorithm = "aes-256-gcm",
                Nonce = nonce,
                Ciphertext = ct,
                Tag = tag,
            },
        });

        return name;
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var v in await _volumeService.ListAllAsync())
        {
            try
            {
                var header = await _volumeService.GetVolumeHeaderAsync(v.Name);
                await _volumeService.LockAsync(v.Name, header.OwnerUser);
            }
            catch (Exception) { }
        }
        try { if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true); } catch (Exception) { }
    }
}
