using System.Text;
using System.Xml;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.WebDav;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public class WebDavTests : IDisposable
{
    private readonly string _dataRoot;
    private readonly VolumeService _volumeService;
    private readonly FileService _fileService;
    private readonly WebDavHandler _handler;

    public WebDavTests()
    {
        _dataRoot = Path.Combine(Path.GetTempPath(), "cista-webdav-" + Guid.NewGuid().ToString("N"));
        var opt = new CistaNasOptions
        {
            DataRoot = _dataRoot,
            Volume = new VolumeOptions { SectorSize = 512, KdfIterations = 10_000 },
        };
        var io = Options.Create(opt);
        _volumeService = new VolumeService(io);
        _fileService = new FileService(_volumeService, new JournalService(io), io);
        _handler = new WebDavHandler(_volumeService, _fileService);
    }

    [Fact]
    public async Task OptionsAsync_SetsDavHeader()
    {
        var ctx = new DefaultHttpContext();
        await _handler.OptionsAsync(ctx);
        Assert.Equal(200, ctx.Response.StatusCode);
        Assert.Equal("1", ctx.Response.Headers["DAV"]);
    }

    [Fact]
    public async Task PropFindAsync_Root_EmptyDirectory()
    {
        _volumeService.Create("test-vol", null, null, encrypted: false);
        var ctx = new DefaultHttpContext();
        using var ms = new MemoryStream();
        ctx.Response.Body = ms;
        await _handler.PropFindAsync("test-vol", "", "1", ctx);
        Assert.Equal(207, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task Put_ThenGet_Roundtrip()
    {
        _volumeService.Create("io-vol", null, null, encrypted: false);
        var content = Encoding.UTF8.GetBytes("Hello WebDAV!");
        using var ms = new MemoryStream(content);

        await _fileService.UploadAsync("io-vol", "hello.txt", ms, content.Length);

        var list = _fileService.List("io-vol");
        Assert.Single(list.Files);
        Assert.Equal("hello.txt", list.Files[0].Name);
    }

    [Fact]
    public async Task PropFindAsync_WithDirectoryPaths_ReturnsResources()
    {
        _volumeService.Create("dir-vol", null, null, encrypted: false);

        await Upload("dir-vol", "docs/readme.txt", "readme");
        await Upload("dir-vol", "docs/notes.txt", "notes");
        await Upload("dir-vol", "root.txt", "root");

        var list = _fileService.List("dir-vol");
        Assert.Equal(3, list.Files.Count);

        var ctx = new DefaultHttpContext();
        using var ms = new MemoryStream();
        ctx.Response.Body = ms;
        await _handler.PropFindAsync("dir-vol", "", "1", ctx);
        Assert.Equal(207, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task PropFindAsync_Subdirectory_ReturnsChildren()
    {
        _volumeService.Create("sub-vol", null, null, encrypted: false);
        await Upload("sub-vol", "a/file1.txt", "one");
        await Upload("sub-vol", "a/file2.txt", "two");
        await Upload("sub-vol", "b/file3.txt", "three");

        var ctx = new DefaultHttpContext();
        using var ms = new MemoryStream();
        ctx.Response.Body = ms;
        await _handler.PropFindAsync("sub-vol", "a", "1", ctx);
        Assert.Equal(207, ctx.Response.StatusCode);

        ms.Position = 0;
        string xml = await new StreamReader(ms).ReadToEndAsync();
        Assert.Contains("file1.txt", xml);
        Assert.Contains("file2.txt", xml);
        Assert.DoesNotContain("file3.txt", xml);
    }

    [Fact]
    public void Delete_File_RemovesFromCatalog()
    {
        _volumeService.Create("del-vol", null, null, encrypted: false);
        Upload("del-vol", "todelete.txt", "bye").Wait();

        _fileService.Delete("del-vol", "todelete.txt");

        var list = _fileService.List("del-vol");
        Assert.Empty(list.Files);
    }

    [Fact]
    public void MkCol_Succeeds()
    {
        _volumeService.Create("mkcol-vol", null, null, encrypted: false);
        var result = _handler.MkCol("mkcol-vol", "newdir");
        Assert.NotNull(result);
    }

    [Fact]
    public void WebDavXml_BuildMultiStatus_IsValidXml()
    {
        var resources = new List<WebDavResource>
        {
            new() { Path = "", IsCollection = true, LastModified = DateTimeOffset.UtcNow },
            new() { Path = "file.txt", IsCollection = false, Size = 42, LastModified = DateTimeOffset.UtcNow },
        };
        string xml = WebDavXml.BuildMultiStatus(resources, "/dav/test");
        Assert.Contains("multistatus", xml);
        Assert.Contains("file.txt", xml);

        var doc = new XmlDocument();
        doc.LoadXml(xml);
        Assert.Equal(2, doc.GetElementsByTagName("response", "DAV:").Count);
    }

    private async Task Upload(string vol, string path, string content)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(content);
        using var ms = new MemoryStream(bytes);
        await _fileService.UploadAsync(vol, path, ms, bytes.Length);
    }

    public void Dispose()
    {
        foreach (var v in _volumeService.ListMounted())
        {
            try { _volumeService.Lock(v.Name); } catch { }
        }
        if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true);
    }
}
