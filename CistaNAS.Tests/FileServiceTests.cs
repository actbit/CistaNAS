using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using Microsoft.Extensions.DependencyInjection;

namespace CistaNAS.Tests;

public class FileServiceTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _vs;

    public FileServiceTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _vs = _sp.GetRequiredService<VolumeService>();
    }

    private FileService GetFileService()
    {
        using var scope = _sp.CreateAsyncScope();
        return scope.ServiceProvider.GetRequiredService<FileService>();
    }

    [Fact]
    public async Task UploadAndDownload_Roundtrip()
    {
        string vol = await MountVol("io-test");
        var fs = GetFileService();
        byte[] data = "Hello, CistaNAS!"u8.ToArray();

        using var ms = new MemoryStream(data);
        await fs.UploadAsync(vol, "hello.txt", ms, data.Length);

        var dl = await fs.DownloadAsync(vol, "hello.txt");
        using var dlStream = dl.Stream;
        var result = new byte[dl.Length];
        await dlStream.ReadExactlyAsync(result);
        Assert.Equal(data, result);
    }

    [Fact]
    public async Task Upload_OverwriteShorter_ReusesOffset()
    {
        string vol = await MountVol("overwrite-short");
        var fs = GetFileService();

        byte[] data1 = new byte[1000];
        using (var ms = new MemoryStream(data1))
            await fs.UploadAsync(vol, "file.bin", ms, data1.Length);

        byte[] data2 = new byte[500];
        using (var ms = new MemoryStream(data2))
            await fs.UploadAsync(vol, "file.bin", ms, data2.Length);

        var dl = await fs.DownloadAsync(vol, "file.bin");
        using var dlStream = dl.Stream;
        Assert.Equal(500, dl.Length);
        var result = new byte[500];
        await dlStream.ReadExactlyAsync(result);
        Assert.Equal(data2, result);
    }

    [Fact]
    public async Task Upload_OverwriteLonger_Appends()
    {
        string vol = await MountVol("overwrite-long");
        var fs = GetFileService();

        byte[] data1 = new byte[500];
        using (var ms = new MemoryStream(data1))
            await fs.UploadAsync(vol, "file.bin", ms, data1.Length);

        byte[] data2 = new byte[1500];
        Random.Shared.NextBytes(data2);
        using (var ms = new MemoryStream(data2))
            await fs.UploadAsync(vol, "file.bin", ms, data2.Length);

        var dl = await fs.DownloadAsync(vol, "file.bin");
        using var dlStream = dl.Stream;
        Assert.Equal(1500, dl.Length);
        var result = new byte[1500];
        await dlStream.ReadExactlyAsync(result);
        Assert.Equal(data2, result);
    }

    [Fact]
    public async Task Upload_EarlyEof_RecordsActualLength()
    {
        string vol = await MountVol("early-eof");
        var fs = GetFileService();

        byte[] data = new byte[300];
        using var ms = new MemoryStream(data);
        var meta = await fs.UploadAsync(vol, "short.bin", ms, contentLength: 1000);

        Assert.Equal(300, meta.Length);
    }

    [Fact]
    public async Task Download_NotFound_Throws()
    {
        string vol = await MountVol("dl-404");
        var fs = GetFileService();
        await Assert.ThrowsAsync<FileServiceException>(() => fs.DownloadAsync(vol, "nope.txt"));
    }

    [Fact]
    public async Task Delete_NotFound_Throws()
    {
        string vol = await MountVol("del-404");
        var fs = GetFileService();
        await Assert.ThrowsAsync<FileServiceException>(() => fs.DeleteAsync(vol, "nope.txt"));
    }

    [Fact]
    public async Task Upload_Delete_ListReflects()
    {
        string vol = await MountVol("list-test");
        var fs = GetFileService();

        byte[] data = "data"u8.ToArray();
        using (var ms = new MemoryStream(data))
            await fs.UploadAsync(vol, "a.txt", ms, data.Length);
        using (var ms = new MemoryStream(data))
            await fs.UploadAsync(vol, "b.txt", ms, data.Length);

        var list = await fs.ListAsync(vol);
        Assert.Equal(2, list.Files.Count);

        await fs.DeleteAsync(vol, "a.txt");
        list = await fs.ListAsync(vol);
        Assert.Single(list.Files);
        Assert.Equal("b.txt", list.Files[0].Name);
    }

    [Fact]
    public async Task List_EmptyVolume_ReturnsEmpty()
    {
        string vol = await MountVol("empty-list");
        var fs = GetFileService();
        var list = await fs.ListAsync(vol);
        Assert.Empty(list.Files);
    }

    private async Task<string> MountVol(string name)
    {
        await _vs.CreateAsync(name, "testuser", "testpw", encrypted: false);
        return name;
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var v in await _vs.ListAllAsync())
        {
            try
            {
                var header = await _vs.GetVolumeHeaderAsync(v.Name);
                await _vs.LockAsync(v.Name, header.OwnerUser);
            }
            catch (Exception) { }
        }
        try { if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true); } catch (Exception) { }
    }
}
