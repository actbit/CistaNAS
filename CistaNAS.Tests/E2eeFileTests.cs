using System.Security.Cryptography;
using CistaNAS.Client.Crypto;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public class E2eeFileTests : IDisposable
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
        return new E2eeFileService(_volumeService, storage, opt);
    }

    [Fact]
    public void CreateFile_ReturnsEntryWithFileId()
    {
        string vol = MountE2ee("test-create");
        var e2eeFs = GetE2eeFileService();
        var entry = e2eeFs.CreateFile(vol, new E2eeCreateFileRequest("enc-name-abc", 2048, 2));

        Assert.False(string.IsNullOrEmpty(entry.FileId));
        Assert.Equal("enc-name-abc", entry.EncryptedName);
        Assert.Equal(2048, entry.EncryptedLength);
        Assert.Equal(2, entry.ChunkCount);
    }

    [Fact]
    public async Task UploadAndDownloadChunk_Roundtrip()
    {
        string vol = MountE2ee("test-io");
        const int chunkSize = 4096;

        var e2eeFs = GetE2eeFileService();
        var entry = e2eeFs.CreateFile(vol, new E2eeCreateFileRequest("enc-file", chunkSize * 2 + 16 * 2 + 16, 2));

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

        var (stream0, len0) = e2eeFs.DownloadChunk(vol, entry.FileId, 0);
        byte[] dl0 = new byte[len0];
        using (stream0) await stream0.ReadExactlyAsync(dl0);
        Assert.Equal(encChunk0, dl0);

        var (stream1, len1) = e2eeFs.DownloadChunk(vol, entry.FileId, 1);
        byte[] dl1 = new byte[len1];
        using (stream1) await stream1.ReadExactlyAsync(dl1);
        Assert.Equal(encChunk1, dl1);

        byte[] dec0 = E2eeCrypto.DecryptChunk(dl0, fileKey, 0, out var salt0);
        Assert.Equal(fileSalt, salt0);
        Assert.Equal(plain0, dec0);

        byte[] dec1 = E2eeCrypto.DecryptChunk(dl1, fileKey, 1, out _);
        Assert.Equal(plain1, dec1);
    }

    [Fact]
    public void ListFiles_ReturnsCreatedFiles()
    {
        string vol = MountE2ee("test-list");
        var e2eeFs = GetE2eeFileService();
        e2eeFs.CreateFile(vol, new E2eeCreateFileRequest("enc-a", 100, 1));
        e2eeFs.CreateFile(vol, new E2eeCreateFileRequest("enc-b", 200, 1));

        var result = e2eeFs.ListFiles(vol);
        Assert.Equal(2, result.Files.Count);
        Assert.Contains(result.Files, f => f.EncryptedName == "enc-a");
        Assert.Contains(result.Files, f => f.EncryptedName == "enc-b");
    }

    [Fact]
    public void DeleteFile_RemovesFromCatalog()
    {
        string vol = MountE2ee("test-delete");
        var e2eeFs = GetE2eeFileService();
        var entry = e2eeFs.CreateFile(vol, new E2eeCreateFileRequest("to-delete", 100, 1));

        Assert.Single(e2eeFs.ListFiles(vol).Files);
        e2eeFs.DeleteFile(vol, entry.FileId);
        Assert.Empty(e2eeFs.ListFiles(vol).Files);
    }

    [Fact]
    public void FinalizeFile_UpdatesLength()
    {
        string vol = MountE2ee("test-finalize");
        var e2eeFs = GetE2eeFileService();
        var entry = e2eeFs.CreateFile(vol, new E2eeCreateFileRequest("enc", 2048, 2));

        e2eeFs.FinalizeFile(vol, entry.FileId, new E2eeFinalizeFileRequest(1500));

        var list = e2eeFs.ListFiles(vol);
        Assert.Single(list.Files);
        Assert.Equal(1500, list.Files[0].EncryptedLength);
    }

    [Fact]
    public void DeleteFile_NonExistent_Throws()
    {
        string vol = MountE2ee("test-del-missing");
        var e2eeFs = GetE2eeFileService();
        Assert.Throws<FileServiceException>(() =>
            e2eeFs.DeleteFile(vol, "nonexistent-id"));
    }

    private string MountE2ee(string name)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek("testuser", "testpass", salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(_masterKey, kek);

        _volumeService.CreateE2ee(name, "testuser", new VolumeHeader.UserWrappedKey
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

    public void Dispose()
    {
        foreach (var v in _volumeService.ListAll())
        {
            try { _volumeService.Lock(v.Name); } catch { }
        }
        try { if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true); } catch { }
    }
}
