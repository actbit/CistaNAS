using System.Text;
using System.Xml;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Services;
using CistaNAS.Web.WebDav;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public class WebDavTests : IDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _volumeService;

    public WebDavTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _volumeService = _sp.GetRequiredService<VolumeService>();
    }

    private (FileService fs, WebDavHandler handler) GetWebDavServices()
    {
        using var scope = _sp.CreateAsyncScope();
        var fs = scope.ServiceProvider.GetRequiredService<FileService>();
        var opt = _sp.GetRequiredService<IOptions<CistaNasOptions>>();
        var storage = _sp.GetRequiredService<CistaNAS.Web.Storage.IStorageProvider>();
        var e2eeFs = new E2eeFileService(_volumeService, storage, opt);
        var handler = new WebDavHandler(_volumeService, fs, e2eeFs);
        return (fs, handler);
    }

    private DefaultHttpContext NewContext(string username = "testuser")
    {
        var ctx = new DefaultHttpContext();
        ctx.User = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity(
            [
                new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, username),
            ], "test"));
        return ctx;
    }

    [Fact]
    public async Task OptionsAsync_SetsDavHeader()
    {
        var (_, handler) = GetWebDavServices();
        var ctx = new DefaultHttpContext();
        await handler.OptionsAsync(ctx);
        Assert.Equal(200, ctx.Response.StatusCode);
        Assert.Equal("1", ctx.Response.Headers["DAV"]);
    }

    [Fact]
    public async Task PropFindAsync_Root_EmptyDirectory()
    {
        var (fs, handler) = GetWebDavServices();
        _volumeService.Create("test-vol", null, null, encrypted: false);
        var ctx = NewContext();
        using var ms = new MemoryStream();
        ctx.Response.Body = ms;
        await handler.PropFindAsync("test-vol", "", "1", ctx);
        Assert.Equal(207, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task Put_ThenGet_Roundtrip()
    {
        var (fs, _) = GetWebDavServices();
        _volumeService.Create("io-vol", null, null, encrypted: false);
        var content = Encoding.UTF8.GetBytes("Hello WebDAV!");
        using var ms = new MemoryStream(content);
        await fs.UploadAsync("io-vol", "hello.txt", ms, content.Length);
        var list = await fs.ListAsync("io-vol");
        Assert.Single(list.Files);
    }

    [Fact]
    public async Task PropFindAsync_WithDirectoryPaths()
    {
        var (fs, handler) = GetWebDavServices();
        _volumeService.Create("dir-vol", null, null, encrypted: false);
        await Upload(fs, "dir-vol", "docs/readme.txt", "readme");
        await Upload(fs, "dir-vol", "docs/notes.txt", "notes");
        await Upload(fs, "dir-vol", "root.txt", "root");

        var ctx = NewContext();
        using var ms = new MemoryStream();
        ctx.Response.Body = ms;
        await handler.PropFindAsync("dir-vol", "", "1", ctx);
        Assert.Equal(207, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task PropFindAsync_Subdirectory()
    {
        var (fs, handler) = GetWebDavServices();
        _volumeService.Create("sub-vol", null, null, encrypted: false);
        await Upload(fs, "sub-vol", "a/file1.txt", "one");
        await Upload(fs, "sub-vol", "a/file2.txt", "two");
        await Upload(fs, "sub-vol", "b/file3.txt", "three");

        var ctx = NewContext();
        using var ms = new MemoryStream();
        ctx.Response.Body = ms;
        await handler.PropFindAsync("sub-vol", "a", "1", ctx);
        Assert.Equal(207, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task Delete_File()
    {
        var (fs, _) = GetWebDavServices();
        _volumeService.Create("del-vol", null, null, encrypted: false);
        await Upload(fs, "del-vol", "todelete.txt", "bye");
        await fs.DeleteAsync("del-vol", "todelete.txt");
        Assert.Empty((await fs.ListAsync("del-vol")).Files);
    }

    [Fact]
    public void MkCol_Succeeds()
    {
        var (_, handler) = GetWebDavServices();
        _volumeService.Create("mkcol-vol", null, null, encrypted: false);
        var result = handler.MkCol("mkcol-vol", "newdir", NewContext());
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
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        Assert.Equal(2, doc.GetElementsByTagName("response", "DAV:").Count);
    }

    private static async Task Upload(FileService fs, string vol, string path, string content)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(content);
        using var ms = new MemoryStream(bytes);
        await fs.UploadAsync(vol, path, ms, bytes.Length);
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
