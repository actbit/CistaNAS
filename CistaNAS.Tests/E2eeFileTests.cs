using System.Security.Cryptography;
using CistaNAS.Client.Crypto;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public class E2eeFileTests : IDisposable
{
    private readonly string _dataRoot;
    private readonly VolumeService _volumeService;
    private readonly E2eeFileService _e2eeFs;
    private readonly byte[] _masterKey;

    public E2eeFileTests()
    {
        _dataRoot = Path.Combine(Path.GetTempPath(), "cista-e2ee-" + Guid.NewGuid().ToString("N"));
        var opt = new CistaNasOptions
        {
            DataRoot = _dataRoot,
            Volume = new VolumeOptions { SectorSize = 512, KdfIterations = 10_000 },
        };
        var io = Options.Create(opt);
        var gs = new GroupStore(io, new ServiceCollection().BuildServiceProvider());
        var sp = new ServiceCollection().AddLogging().BuildServiceProvider();
        var us = new UserStore(io, sp.GetRequiredService<ILogger<UserStore>>(), sp);
        _volumeService = new VolumeService(io, gs, us);
        _e2eeFs = new E2eeFileService(_volumeService, io);
        _masterKey = RandomNumberGenerator.GetBytes(32);
    }

    [Fact]
    public void CreateFile_ReturnsEntryWithFileId()
    {
        string vol = MountE2ee("test-create");
        var entry = _e2eeFs.CreateFile(vol, new E2eeCreateFileRequest("enc-name-abc", 2048, 2));

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

        var entry = _e2eeFs.CreateFile(vol, new E2eeCreateFileRequest("enc-file", chunkSize * 2 + 16 * 2 + 16, 2));

        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(_masterKey, fileSalt);
        byte[] plain0 = RandomNumberGenerator.GetBytes(chunkSize);
        byte[] plain1 = RandomNumberGenerator.GetBytes(1000);

        byte[] encChunk0 = E2eeCrypto.EncryptChunk(plain0, fileKey, 0, fileSalt, isFirstChunk: true);
        byte[] encChunk1 = E2eeCrypto.EncryptChunk(plain1, fileKey, 1, fileSalt, isFirstChunk: false);

        using (var ms0 = new MemoryStream(encChunk0))
            await _e2eeFs.UploadChunkAsync(vol, entry.FileId, 0, ms0, encChunk0.Length);
        using (var ms1 = new MemoryStream(encChunk1))
            await _e2eeFs.UploadChunkAsync(vol, entry.FileId, 1, ms1, encChunk1.Length);

        var (stream0, len0) = _e2eeFs.DownloadChunk(vol, entry.FileId, 0);
        byte[] dl0 = new byte[len0];
        using (stream0) await stream0.ReadAsync(dl0);
        Assert.Equal(encChunk0, dl0);

        var (stream1, len1) = _e2eeFs.DownloadChunk(vol, entry.FileId, 1);
        byte[] dl1 = new byte[len1];
        using (stream1) await stream1.ReadAsync(dl1);
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
        _e2eeFs.CreateFile(vol, new E2eeCreateFileRequest("enc-a", 100, 1));
        _e2eeFs.CreateFile(vol, new E2eeCreateFileRequest("enc-b", 200, 1));

        var result = _e2eeFs.ListFiles(vol);
        Assert.Equal(2, result.Files.Count);
        Assert.Contains(result.Files, f => f.EncryptedName == "enc-a");
        Assert.Contains(result.Files, f => f.EncryptedName == "enc-b");
    }

    [Fact]
    public void DeleteFile_RemovesFromCatalog()
    {
        string vol = MountE2ee("test-delete");
        var entry = _e2eeFs.CreateFile(vol, new E2eeCreateFileRequest("to-delete", 100, 1));

        Assert.Single(_e2eeFs.ListFiles(vol).Files);
        _e2eeFs.DeleteFile(vol, entry.FileId);
        Assert.Empty(_e2eeFs.ListFiles(vol).Files);
    }

    [Fact]
    public void FinalizeFile_UpdatesLength()
    {
        string vol = MountE2ee("test-finalize");
        var entry = _e2eeFs.CreateFile(vol, new E2eeCreateFileRequest("enc", 2048, 2));

        _e2eeFs.FinalizeFile(vol, entry.FileId, new E2eeFinalizeFileRequest(1500));

        var list = _e2eeFs.ListFiles(vol);
        Assert.Single(list.Files);
        Assert.Equal(1500, list.Files[0].EncryptedLength);
    }

    [Fact]
    public void DeleteFile_NonExistent_Throws()
    {
        string vol = MountE2ee("test-del-missing");
        Assert.Throws<FileServiceException>(() =>
            _e2eeFs.DeleteFile(vol, "nonexistent-id"));
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
        if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true);
    }
}
