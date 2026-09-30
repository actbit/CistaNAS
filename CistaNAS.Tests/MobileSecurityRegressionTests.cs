using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Abstractions;
using CistaNAS.Mobile.Core.Services;
using CistaNAS.Mobile.Core.ViewModels;
using CistaNAS.Shared.Crypto;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

namespace CistaNAS.Tests;

public sealed class MobileSecurityRegressionTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"cista-mobile-security-{Guid.NewGuid():N}");
    private DiskFileCacheProvider Cache => new(_directory);

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, true);
    }

    [Fact]
    public async Task DefaultHttpHandler_CanLoginOverRealHttp()
    {
        await using var server = CreateServer();
        server.MapPost("/api/v1/auth/login", () => Results.Json(new { accessToken = "test-token" }));
        await server.StartAsync();
        using var session = new ApiSession();
        session.ConfigureServer(server.Urls.Single());
        Assert.Equal("test-token", await session.Api.LoginAsync("user", "password"));
    }

    [Fact]
    public async Task LoginRedirect_DoesNotForwardCredentialsToAnotherServer()
    {
        int forwarded = 0;
        await using var destination = CreateServer();
        destination.MapPost("/api/v1/auth/login", () =>
        {
            Interlocked.Increment(ref forwarded);
            return Results.Json(new { accessToken = "stolen" });
        });
        await destination.StartAsync();
        await using var source = CreateServer();
        source.MapPost("/api/v1/auth/login", () => Results.Redirect(
            destination.Urls.Single() + "/api/v1/auth/login", preserveMethod: true));
        await source.StartAsync();
        using var session = new ApiSession();
        session.ConfigureServer(source.Urls.Single());
        var error = await Assert.ThrowsAsync<HttpRequestException>(() => session.Api.LoginAsync("user", "secret"));
        Assert.Equal(HttpStatusCode.TemporaryRedirect, error.StatusCode);
        Assert.Equal(0, forwarded);
    }

    [Theory]
    [InlineData("../outside")]
    [InlineData("..\\outside")]
    [InlineData("/absolute")]
    [InlineData("C:\\absolute")]
    [InlineData(".")]
    [InlineData("data:stream")]
    public void CacheRejectsPathsOutsideItsDirectory(string name) =>
        Assert.Throws<ArgumentException>(() => Cache.OpenWrite(name));

    [Fact]
    public async Task ChangingServerAfterRequest_DoesNotSendPreviousToken()
    {
        var destinations = new List<Uri>();
        var handler = new Handler(request =>
        {
            destinations.Add(request.RequestUri!);
            return new StringContent("{\"accessToken\":\"token\"}", System.Text.Encoding.UTF8, "application/json");
        });
        using var session = new ApiSession(handler);
        session.ConfigureServer("http://first/");
        session.SetToken("previous-server-token");
        await session.Api.LoginAsync("user", "password");
        Assert.Equal("Bearer previous-server-token", handler.LastAuthorization);
        session.ConfigureServer("http://second/");
        await session.Api.LoginAsync("user", "password");
        Assert.Null(handler.LastAuthorization);
        Assert.Equal(new[] { "first", "second" }, destinations.Select(uri => uri.Host));
    }

    [Fact]
    public async Task ReopeningSameFile_DoesNotReplacePreviouslyGrantedViewerPath()
    {
        var launcher = new Viewer();
        using var app = CreateApp(new Handler(_ => new ByteArrayContent([1, 2, 3])), launcher);
        var viewer = CreateViewer(app);
        await viewer.RetryCommand.ExecuteAsync(null);
        await viewer.RetryCommand.ExecuteAsync(null);
        Assert.Null(viewer.Error);
        Assert.Equal(2, launcher.Paths.Count);
        Assert.NotEqual(launcher.Paths[0], launcher.Paths[1]);
        Assert.All(launcher.Paths, path => Assert.Equal(".mp4", Path.GetExtension(path)));
        Assert.Equal(new byte[] { 1, 2, 3 }, await File.ReadAllBytesAsync(launcher.Paths[0]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedTransferOrMissingViewer_RemovesDecryptedCache(bool failedTransfer)
    {
        var launcher = new Viewer { CanLaunch = false };
        using var app = CreateApp(new Handler(_ => failedTransfer
            ? new StreamContent(new InterruptedStream()) : new ByteArrayContent([1, 2, 3])), launcher);
        var viewer = CreateViewer(app);
        await viewer.RetryCommand.ExecuteAsync(null);
        Assert.Empty(Directory.GetFiles(_directory));
        if (failedTransfer)
        {
            Assert.NotNull(viewer.Error);
            Assert.Empty(launcher.Paths);
        }
        else Assert.Null(viewer.Error);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LogoutOrNavigationDuringTransfer_CancelsAndNeverLaunches(bool logout)
    {
        var stream = new PendingStream();
        var launcher = new Viewer();
        using var app = CreateApp(new Handler(_ => new StreamContent(stream)), launcher);
        var viewer = CreateViewer(app);
        Task transfer = viewer.RetryCommand.ExecuteAsync(null);
        await stream.Waiting.Task.WaitAsync(TimeSpan.FromSeconds(10));
        if (logout) new VolumesViewModel(app).LogoutCommand.Execute(null);
        else viewer.OnNavigatedFrom();
        await transfer.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Empty(launcher.Paths);
        Assert.Empty(Directory.GetFiles(_directory));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LogoutOrUnauthorized_ClearsTokenKeysAndCache(bool unauthorized)
    {
        var handler = new Handler(_ => new ByteArrayContent([])) { Status = HttpStatusCode.Unauthorized };
        using var app = CreateApp(handler, new Viewer());
        app.Session.SetToken("secret-token");
        app.E2ee.StoreKey("vol", E2eeCrypto.GenerateMasterKey(), 1024);
        byte[] storedKey = app.E2ee.GetMasterKey("vol");
        using (var output = Cache.OpenWrite("secret.txt")) output.Write([1, 2, 3]);
        bool expired = false;
        app.SessionExpired += () => expired = true;
        if (unauthorized)
        {
            await Assert.ThrowsAsync<HttpRequestException>(() => app.Session.Api.ListVolumesAsync());
            Assert.True(expired);
        }
        else new VolumesViewModel(app).LogoutCommand.Execute(null);
        Assert.False(app.E2ee.HasKey("vol"));
        Assert.All(storedKey, b => Assert.Equal(0, b));
        Assert.Empty(Directory.GetFiles(_directory));
        await Assert.ThrowsAsync<HttpRequestException>(() => app.Session.Api.ListVolumesAsync());
        Assert.Null(handler.LastAuthorization);
    }

    [Fact]
    public void StartupAndDispose_RemovePreviousPlaintextCache()
    {
        using (var output = Cache.OpenWrite("old.txt")) output.WriteByte(42);
        var app = CreateApp(new Handler(_ => new ByteArrayContent([])), new Viewer());
        Assert.Empty(Directory.GetFiles(_directory));
        using (var output = Cache.OpenWrite("new.txt")) output.WriteByte(42);
        app.Dispose();
        Assert.Empty(Directory.GetFiles(_directory));
    }

    [Fact]
    public void ReplacingSessionKeys_ErasesPreviousKeyBuffers()
    {
        using var session = new E2eeSession();
        session.StoreKey("vol", E2eeCrypto.GenerateMasterKey(), 1024);
        byte[] oldMaster = session.GetMasterKey("vol");
        session.StoreKey("vol", E2eeCrypto.GenerateMasterKey(), 1024);
        Assert.All(oldMaster, b => Assert.Equal(0, b));
        session.StoreV2State("vol", "id", new Dictionary<int, byte[]> { [1] = E2eeCrypto.GenerateMasterKey() });
        byte[] oldGroup = session.GetV2State("vol").GetGroupKey(1);
        session.StoreV2State("vol", "id", new Dictionary<int, byte[]> { [2] = E2eeCrypto.GenerateMasterKey() });
        Assert.All(oldGroup, b => Assert.Equal(0, b));
    }

    private static WebApplication CreateServer()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration["AllowedHosts"] = "127.0.0.1";
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        return builder.Build();
    }

    private AppServices CreateApp(HttpMessageHandler handler, Viewer viewer)
    {
        var app = new AppServices(new MemorySecureKeyStore(), new MemoryAppSettings(), Cache, viewer, handler);
        app.Session.ConfigureServer("http://test/");
        return app;
    }

    private static ExternalViewerViewModel CreateViewer(AppServices app) => new(app,
        new FileBrowserViewModel(app, new VolumeListItem { Name = "vol", EncryptionMode = "server" }),
        new FileItem { Name = "clip.mp4", FullPath = "clip.mp4", IsFolder = false });

    private sealed class Viewer : IExternalViewerLauncher
    {
        public bool CanLaunch { get; init; } = true;
        public List<string> Paths { get; } = [];
        public Task<bool> LaunchAsync(string filePath, string mimeType)
        {
            Paths.Add(filePath);
            return Task.FromResult(CanLaunch);
        }
    }

    private sealed class Handler(Func<HttpRequestMessage, HttpContent> content) : HttpMessageHandler
    {
        public HttpStatusCode Status { get; init; } = HttpStatusCode.OK;
        public string? LastAuthorization { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            LastAuthorization = request.Headers.Authorization?.ToString();
            return Task.FromResult(new HttpResponseMessage(Status) { Content = content(request) });
        }
    }

    private sealed class InterruptedStream : MemoryStream
    {
        public override async Task CopyToAsync(Stream destination, int bufferSize, CancellationToken ct)
        {
            await destination.WriteAsync(new byte[] { 42 }, ct);
            throw new IOException("Interrupted download");
        }
    }

    private sealed class PendingStream : MemoryStream
    {
        public TaskCompletionSource Waiting { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async Task CopyToAsync(Stream destination, int bufferSize, CancellationToken ct)
        {
            await destination.WriteAsync(new byte[] { 42 }, ct);
            Waiting.TrySetResult();
            await Task.Delay(Timeout.Infinite, ct);
        }
    }
}
