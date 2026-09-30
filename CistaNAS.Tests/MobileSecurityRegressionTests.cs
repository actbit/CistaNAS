using CistaNAS.Mobile.Core.Services;
using CistaNAS.Mobile.Core.ViewModels;
using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

namespace CistaNAS.Tests;

public sealed class MobileSecurityRegressionTests
{
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

    [Fact]
    public async Task ChangingServerAfterRequest_DoesNotSendPreviousToken()
    {
        var destinations = new List<Uri>();
        var handler = new Handler((request, _) =>
        {
            destinations.Add(request.RequestUri!);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent("{\"accessToken\":\"token\"}", System.Text.Encoding.UTF8, "application/json") });
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
    public async Task OpeningServerVideo_DoesNotDownloadUntilViewerRequestsRange()
    {
        int requests = 0;
        using var app = CreateApp(new Handler((request, _) =>
        {
            requests++;
            Assert.Equal("bytes=1-2", request.Headers.Range!.ToString());
            var response = new HttpResponseMessage(HttpStatusCode.PartialContent) { Content = new ByteArrayContent([2, 3]) };
            response.Content.Headers.ContentRange = new System.Net.Http.Headers.ContentRangeHeaderValue(1, 2, 3);
            return Task.FromResult(response);
        }));
        using var vm = CreateViewer(app);
        await vm.RetryCommand.ExecuteAsync(null);
        Assert.Null(vm.Error);
        Assert.Equal(0, requests);
        var content = Assert.Single(((RecordingFileViewer)app.Viewer).Launched);
        var buffer = new byte[2];
        Assert.Equal(2, await content.ReadAsync(1, buffer));
        Assert.Equal(new byte[] { 2, 3 }, buffer);
    }

    [Fact]
    public async Task ReopeningAndNavigation_CancelPreviousReaders()
    {
        using var app = CreateApp(new Handler((_, _) => throw new InvalidOperationException("No eager download")));
        using var vm = CreateViewer(app);
        await vm.RetryCommand.ExecuteAsync(null);
        var first = Assert.Single(((RecordingFileViewer)app.Viewer).Launched);
        await vm.RetryCommand.ExecuteAsync(null);
        Assert.True(first.Cancellation.IsCancellationRequested);
        var second = ((RecordingFileViewer)app.Viewer).Launched[1];
        vm.OnNavigatedFrom();
        Assert.True(second.Cancellation.IsCancellationRequested);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => second.ReadAsync(0, new byte[3]).AsTask());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LogoutOrUnauthorized_DuringRead_CancelsWithoutDeadlock(bool unauthorized)
    {
        var waiting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var app = CreateApp(new Handler(async (_, ct) =>
        {
            waiting.TrySetResult();
            if (unauthorized) return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            await Task.Delay(Timeout.Infinite, ct);
            throw new InvalidOperationException();
        }));
        app.Session.SetToken("secret-token");
        app.E2ee.StoreKey("vol", E2eeCrypto.GenerateMasterKey(), 1024);
        byte[] storedKey = app.E2ee.GetMasterKey("vol");
        using var vm = CreateViewer(app);
        await vm.RetryCommand.ExecuteAsync(null);
        var content = Assert.Single(((RecordingFileViewer)app.Viewer).Launched);
        Task read = content.ReadAsync(0, new byte[3]).AsTask();
        await waiting.Task.WaitAsync(TimeSpan.FromSeconds(10));
        if (!unauthorized) app.ClearSession();
        var error = await Record.ExceptionAsync(() => read.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.NotNull(error);
        Assert.IsNotType<TimeoutException>(error);
        Assert.True(read.IsCompleted);
        Assert.True(content.Cancellation.IsCancellationRequested);
        Assert.False(app.E2ee.HasKey("vol"));
        Assert.All(storedKey, b => Assert.Equal(0, b));
        Assert.Empty(((RecordingFileViewer)app.Viewer).Launched);
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

    private static AppServices CreateApp(HttpMessageHandler handler)
    {
        var app = new AppServices(new MemorySecureKeyStore(), new MemoryAppSettings(), new RecordingFileViewer(), handler);
        app.Session.ConfigureServer("http://test/");
        return app;
    }

    private static StreamingViewerViewModel CreateViewer(AppServices app) => new(app,
        new FileBrowserViewModel(app, new VolumeListItem { Name = "vol", EncryptionMode = "server" }),
        new FileItem { Name = "clip.mp4", FullPath = "clip.mp4", IsFolder = false, ServerMeta = new FileMetadata { Name = "clip.mp4", Length = 3 } });

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        public string? LastAuthorization { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            LastAuthorization = request.Headers.Authorization?.ToString();
            return send(request, ct);
        }
    }
}
