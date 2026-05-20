using CistaNAS.Web.Configuration;
using CistaNAS.Web.Journal;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public class FileServiceTests : IDisposable
{
    private readonly string _dataRoot;
    private readonly VolumeService _vs;
    private readonly FileService _fs;

    public FileServiceTests()
    {
        _dataRoot = Path.Combine(Path.GetTempPath(), "cista-file-" + Guid.NewGuid().ToString("N"));
        var opt = new CistaNasOptions
        {
            DataRoot = _dataRoot,
            Volume = new VolumeOptions { SectorSize = 512, KdfIterations = 10_000 },
        };
        var io = Options.Create(opt);
        var gs = new GroupStore(io, new ServiceCollection().BuildServiceProvider());
        var sp = new ServiceCollection().AddLogging().BuildServiceProvider();
        var us = new UserStore(io, sp.GetRequiredService<ILogger<UserStore>>(), sp);
        _vs = new VolumeService(io, gs, us);
        var js = new JournalService(io);
        _fs = new FileService(_vs, js, io);
    }

    [Fact]
    public async Task UploadAndDownload_Roundtrip()
    {
        string vol = MountVol("io-test");
        byte[] data = "Hello, CistaNAS!"u8.ToArray();

        using var ms = new MemoryStream(data);
        await _fs.UploadAsync(vol, "hello.txt", ms, data.Length);

        var dl = _fs.Download(vol, "hello.txt");
        using var dlStream = dl.Stream;
        var result = new byte[dl.Length];
        await dlStream.ReadExactlyAsync(result);
        Assert.Equal(data, result);
    }

    [Fact]
    public async Task Upload_OverwriteShorter_ReusesOffset()
    {
        string vol = MountVol("overwrite-short");

        byte[] data1 = new byte[1000];
        using (var ms = new MemoryStream(data1))
            await _fs.UploadAsync(vol, "file.bin", ms, data1.Length);

        byte[] data2 = new byte[500];
        using (var ms = new MemoryStream(data2))
            await _fs.UploadAsync(vol, "file.bin", ms, data2.Length);

        var dl = _fs.Download(vol, "file.bin");
        using var dlStream = dl.Stream;
        Assert.Equal(500, dl.Length);
        var result = new byte[500];
        await dlStream.ReadExactlyAsync(result);
        Assert.Equal(data2, result);
    }

    [Fact]
    public async Task Upload_OverwriteLonger_Appends()
    {
        string vol = MountVol("overwrite-long");

        byte[] data1 = new byte[500];
        using (var ms = new MemoryStream(data1))
            await _fs.UploadAsync(vol, "file.bin", ms, data1.Length);

        byte[] data2 = new byte[1500];
        Random.Shared.NextBytes(data2);
        using (var ms = new MemoryStream(data2))
            await _fs.UploadAsync(vol, "file.bin", ms, data2.Length);

        var dl = _fs.Download(vol, "file.bin");
        using var dlStream = dl.Stream;
        Assert.Equal(1500, dl.Length);
        var result = new byte[1500];
        await dlStream.ReadExactlyAsync(result);
        Assert.Equal(data2, result);
    }

    [Fact]
    public async Task Upload_EarlyEof_RecordsActualLength()
    {
        string vol = MountVol("early-eof");

        // contentLength を 1000 と宣言するがストリームは 300 バイトしか生成しない
        byte[] data = new byte[300];
        using var ms = new MemoryStream(data);
        var meta = await _fs.UploadAsync(vol, "short.bin", ms, contentLength: 1000);

        Assert.Equal(300, meta.Length);
    }

    [Fact]
    public void Download_NotFound_Throws()
    {
        string vol = MountVol("dl-404");
        Assert.Throws<FileServiceException>(() => _fs.Download(vol, "nope.txt"));
    }

    [Fact]
    public void Delete_NotFound_Throws()
    {
        string vol = MountVol("del-404");
        Assert.Throws<FileServiceException>(() => _fs.Delete(vol, "nope.txt"));
    }

    [Fact]
    public async Task Upload_Delete_ListReflects()
    {
        string vol = MountVol("list-test");

        byte[] data = "data"u8.ToArray();
        using (var ms = new MemoryStream(data))
            await _fs.UploadAsync(vol, "a.txt", ms, data.Length);
        using (var ms = new MemoryStream(data))
            await _fs.UploadAsync(vol, "b.txt", ms, data.Length);

        var list = _fs.List(vol);
        Assert.Equal(2, list.Files.Count);

        _fs.Delete(vol, "a.txt");
        list = _fs.List(vol);
        Assert.Single(list.Files);
        Assert.Equal("b.txt", list.Files[0].Name);
    }

    [Fact]
    public void List_EmptyVolume_ReturnsEmpty()
    {
        string vol = MountVol("empty-list");
        var list = _fs.List(vol);
        Assert.Empty(list.Files);
    }

    private string MountVol(string name)
    {
        _vs.Create(name, "testuser", "testpw", encrypted: false);
        return name;
    }

    public void Dispose()
    {
        foreach (var v in _vs.ListAll())
        {
            try { _vs.Lock(v.Name); } catch { }
        }
        if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true);
    }
}
