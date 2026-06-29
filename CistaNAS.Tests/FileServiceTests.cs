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

    /// <summary>
    /// 既存ファイルより短い上書きで、残領域が旧データ残留ではなくゼロクリアされること。
    /// カタログは短い長さを記録するが、volume.dat 上の残りバイトに旧内容が残らない。
    /// </summary>
    [Fact]
    public async Task Upload_OverwriteShorter_ClearsResidualData()
    {
        string vol = await MountVol("residual");
        var fs = GetFileService();

        byte[] data1 = new byte[1000];
        Array.Fill(data1, (byte)0xAB);
        using (var ms = new MemoryStream(data1))
            await fs.UploadAsync(vol, "file.bin", ms, data1.Length);

        byte[] data2 = new byte[500];
        Array.Fill(data2, (byte)0xCD);
        using (var ms = new MemoryStream(data2))
            await fs.UploadAsync(vol, "file.bin", ms, data2.Length);

        // volume.dat の残領域 [500, 1000) を直接読み、旧データ(0xAB)でなく
        // ゼロクリアされていることを検証（カタログは Length=500 で論理的には見えない領域）
        var (ioGuard, stream, _) = await _vs.GetMountedForIoAsync(vol);
        try
        {
            stream.Seek(500, SeekOrigin.Begin);
            byte[] residual = new byte[500];
            int read = stream.Read(residual, 0, 500);
            Assert.Equal(500, read);
            Assert.All(residual, b => Assert.Equal(0, b));
        }
        finally
        {
            ioGuard.Dispose();
        }
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

    /// <summary>PatchRangeAsync で部分書き込み。未書き換えの末尾が保持される（AesXtsStream セクタ RMW）。</summary>
    [Fact]
    public async Task PatchRange_PartialWrite_PreservesTail()
    {
        string vol = await MountVol("patch-test");
        var fs = GetFileService();

        byte[] initial = new byte[1000];
        for (int i = 0; i < initial.Length; i++) initial[i] = (byte)(i & 0xFF);
        using (var ms = new MemoryStream(initial))
            await fs.UploadAsync(vol, "patch.bin", ms, initial.Length);

        // offset 100 から 50バイト部分書き込み
        byte[] patch = new byte[50];
        Array.Fill(patch, (byte)0xAB);
        using (var pms = new MemoryStream(patch))
            await fs.PatchRangeAsync(vol, "patch.bin", 100, pms, patch.Length);

        var dl = await fs.DownloadAsync(vol, "patch.bin");
        using var dlStream = dl.Stream;
        Assert.Equal(1000, dl.Length);
        var result = new byte[1000];
        await dlStream.ReadExactlyAsync(result);

        for (int i = 0; i < 100; i++) Assert.Equal(initial[i], result[i]);
        for (int i = 100; i < 150; i++) Assert.Equal((byte)0xAB, result[i]);
        for (int i = 150; i < 1000; i++) Assert.Equal(initial[i], result[i]);
    }

    /// <summary>PatchRangeAsync で末尾に追記し、ファイル長が拡張される。</summary>
    [Fact]
    public async Task PatchRange_Append_ExtendsFile()
    {
        string vol = await MountVol("patch-append");
        var fs = GetFileService();

        byte[] initial = new byte[500];
        for (int i = 0; i < initial.Length; i++) initial[i] = (byte)(i & 0xFF);
        using (var ms = new MemoryStream(initial))
            await fs.UploadAsync(vol, "app.bin", ms, initial.Length);

        // offset 500 に 100バイト追記 → 600
        byte[] append = new byte[100];
        Array.Fill(append, (byte)0xCD);
        using (var ams = new MemoryStream(append))
            await fs.PatchRangeAsync(vol, "app.bin", 500, ams, append.Length);

        var dl = await fs.DownloadAsync(vol, "app.bin");
        using var dlStream = dl.Stream;
        Assert.Equal(600, dl.Length);
        var result = new byte[600];
        await dlStream.ReadExactlyAsync(result);
        for (int i = 0; i < 500; i++) Assert.Equal(initial[i], result[i]);
        for (int i = 500; i < 600; i++) Assert.Equal((byte)0xCD, result[i]);
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
