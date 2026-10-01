using System.Net.Http.Json;
using System.Reflection;
using CistaNAS.Wasm.Auth;
using CistaNAS.Wasm.Services;
using Microsoft.JSInterop;

namespace CistaNAS.Tests;

public sealed class BrowserMountedVolumeRegressionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OpeningMountedVolume_PreservesItsCustomChunkSize(bool member)
    {
        var js = new NoopJs();
        using var auth = new WasmAuthStateProvider(js);
        await auth.SetTokenAsync("header.eyJzdWIiOiJhbGljZSJ9.signature", DateTimeOffset.UtcNow.AddMinutes(5));
        await using var crypto = new E2eeInterop(js);
        using var mounts = new ClientVolumeMountService(auth, crypto);
        mounts.MountE2ee("volume", member ? null : "master", 65536, "group-e2ee",
            member ? Guid.NewGuid().ToString("N") : null,
            member ? new Dictionary<int, string> { [1] = Convert.ToBase64String(new byte[32]) } : new Dictionary<int, string>());
        using var http = new HttpClient(new Handler(request => Task.FromResult(request.RequestUri!.AbsolutePath == "/api/v1/volumes"
            ? Json(new[] { new { name = "volume", ownerUser = "alice", encryptionMode = "group-e2ee" } })
            : Json(new { files = Array.Empty<object>() }))))
            { BaseAddress = new Uri("http://test/") };
        var page = CreateFilePage(auth, crypto, mounts, http);
        await InvokeTask(page, "InitializeAsync");
        Assert.Equal(65536, Field(page, "_e2eeChunkSize"));
        Assert.True((bool)Field(page, "_e2eeUnlocked")!);
        await page.DisposeAsync();
    }

    [Fact]
    public async Task MountedV2MemberWithoutMasterKey_IsShownAsUnlocked()
    {
        var js = new NoopJs();
        using var auth = new WasmAuthStateProvider(js);
        await auth.SetTokenAsync("header.eyJzdWIiOiJhbGljZSJ9.signature", DateTimeOffset.UtcNow.AddMinutes(5));
        await using var crypto = new E2eeInterop(js);
        using var mounts = new ClientVolumeMountService(auth, crypto);
        mounts.MountE2ee("volume", null, 65536, "group-e2ee", Guid.NewGuid().ToString("N"),
            new Dictionary<int, string> { [1] = Convert.ToBase64String(new byte[32]) });
        using var http = new HttpClient(new Handler(request => Task.FromResult(request.RequestUri!.AbsolutePath == "/api/v1/volumes"
            ? Json(new[] { new { name = "volume", ownerUser = "alice", encryptionMode = "group-e2ee" } })
            : Json(new { files = Array.Empty<object>() }))))
            { BaseAddress = new Uri("http://test/") };
        var page = CreateFilePage(auth, crypto, mounts, http);
        await InvokeTask(page, "InitializeAsync");
        Assert.True((bool)Field(page, "_e2eeUnlocked")!);
        await page.DisposeAsync();
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task CancelledMount_CannotContinueOrCloseAReplacementPrompt(bool e2ee, bool replace)
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        int followups = 0;
        using var http = new HttpClient(new Handler(request =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/mount", StringComparison.Ordinal)) return pending.Task;
            followups++;
            throw new IOException("obsolete follow-up");
        })) { BaseAddress = new Uri("http://test/") };
        var js = new NoopJs();
        using var auth = new WasmAuthStateProvider(js);
        await auth.SetTokenAsync("header.eyJzdWIiOiJhbGljZSJ9.signature", DateTimeOffset.UtcNow.AddMinutes(5));
        await using var crypto = new E2eeInterop(js);
        using var mounts = new ClientVolumeMountService(auth, crypto);
        var volumes = new CistaNAS.Wasm.Pages.Volumes();
        Inject(volumes, "Auth", auth);
        Inject(volumes, "VolumeApi", new VolumeApiClient(http));
        Inject(volumes, "MountService", mounts);
        Inject(volumes, "E2ee", crypto);
        Inject(volumes, "KeyResolver", new E2eeKeyResolverService(crypto, new VolumeApiClient(http), new E2eeApiClient(http), js));
        Invoke(volumes, "ShowMountDialog", "old-volume", true, e2ee ? "e2ee" : "server");
        SetField(volumes, "_mountPassword", "submitted-secret");
        Task mounting = InvokeTask(volumes, "HandleMount");
        Assert.False(mounting.IsCompleted);
        Invoke(volumes, "CloseMountDialog");
        if (replace) Invoke(volumes, "ShowMountDialog", "current-volume", false, "server");
        pending.SetResult(Json(new { name = "old-volume", ownerUser = "alice", encryptionMode = e2ee ? "e2ee" : "server" }));
        await mounting.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, followups);
        Assert.Equal(replace ? "current-volume" : null, Field(volumes, "_mountTarget"));
        Assert.Null(Field(volumes, "_mountError"));
        Assert.Equal("", Field(volumes, "_mountPassword"));
        volumes.Dispose();
    }

    private static CistaNAS.Wasm.Pages.Files CreateFilePage(WasmAuthStateProvider auth, E2eeInterop crypto,
        ClientVolumeMountService mounts, HttpClient http)
    {
        var page = new CistaNAS.Wasm.Pages.Files { VolumeName = "volume" };
        Inject(page, "Auth", auth);
        Inject(page, "VolumeMountService", mounts);
        Inject(page, "VolumeApi", new VolumeApiClient(http));
        Inject(page, "E2eeApi", new E2eeApiClient(http));
        Inject(page, "E2ee", crypto);
        return page;
    }

    private static void Inject(object page, string name, object value) => page.GetType()
        .GetProperty(name, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(page, value);
    private static object? Field(object page, string name) => page.GetType()
        .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(page);
    private static void SetField(object page, string name, object value) => page.GetType()
        .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(page, value);
    private static object? Invoke(object page, string name, params object[] args) => page.GetType()
        .GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(page, args);
    private static Task InvokeTask(object page, string name, params object[] args) => (Task)Invoke(page, name, args)!;
    private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK) { Content = JsonContent.Create(value) };
    private sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request); }
    private sealed class NoopJs : IJSRuntime
    {
        public ValueTask<T> InvokeAsync<T>(string identifier, object?[]? args) => ValueTask.FromResult(default(T)!);
        public ValueTask<T> InvokeAsync<T>(string identifier, CancellationToken ct, object?[]? args) => InvokeAsync<T>(identifier, args);
    }
}
