using System.Net.Http.Json;
using System.Reflection;
using CistaNAS.Wasm.Auth;
using CistaNAS.Wasm.Services;
using Microsoft.JSInterop;

namespace CistaNAS.Tests;

public sealed class BrowserPageLifecycleTests
{
    [Fact]
    public async Task LeavingFilesDuringDownload_CannotOpenTheAbandonedDownload()
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var http = new HttpClient(new Handler(_ => pending.Task)) { BaseAddress = new Uri("http://test/") };
        var js = new RecordingJs();
        using var auth = new WasmAuthStateProvider(js);
        await auth.SetTokenAsync("header.eyJzdWIiOiJhbGljZSJ9.signature", DateTimeOffset.UtcNow.AddMinutes(5));
        await using var crypto = new E2eeInterop(js);
        using var mounts = new ClientVolumeMountService(auth, crypto);
        var page = new CistaNAS.Wasm.Pages.Files { VolumeName = "volume" };
        Inject(page, "Auth", auth);
        Inject(page, "VolumeMountService", mounts);
        Inject(page, "FileApi", new FileApiClient(http));
        Inject(page, "JS", js);
        Task download = InvokeTask(page, "DownloadFile", new CistaNAS.Wasm.Models.FileMetadata { Name = "secret.txt", Length = 3 });
        Assert.False(download.IsCompleted);
        await page.DisposeAsync();
        pending.SetResult(Json(new { token = "abandoned-download-token" }));
        await download.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, js.Downloads);
    }

    private sealed class RecordingJs : IJSRuntime
    {
        public int Downloads;
        public ValueTask<T> InvokeAsync<T>(string identifier, object?[]? args)
        { if (identifier == "cista.openUrl") Downloads++; return ValueTask.FromResult(default(T)!); }
        public ValueTask<T> InvokeAsync<T>(string identifier, CancellationToken ct, object?[]? args) => InvokeAsync<T>(identifier, args);
    }
    [Theory]
    [InlineData("close")]
    [InlineData("replace")]
    [InlineData("login")]
    public async Task PendingPreviewReplacement_CannotReopenAnAbandonedSelection(string change)
    {
        var js = new PausedMediaJs();
        using var auth = new WasmAuthStateProvider(js);
        await auth.SetTokenAsync("header.eyJzdWIiOiJhbGljZSJ9.signature", DateTimeOffset.UtcNow.AddMinutes(5));
        var page = new CistaNAS.Wasm.Pages.Files();
        Inject(page, "Auth", auth);
        Inject(page, "JS", js);
        SetField(page, "_previewElementId", "previous-media");
        SetField(page, "_selectedFile", "previous.png");
        Task obsolete = InvokeTask(page, "PreviewMedia", "obsolete.png");
        await js.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Task? replacement = null;
        if (change == "close") _ = InvokeTask(page, "ClosePreview");
        if (change == "replace") replacement = InvokeTask(page, "PreviewMedia", "current.png");
        if (change == "login")
        {
            await auth.LogoutAsync();
            await auth.SetTokenAsync("header.eyJzdWIiOiJib2IifQ.signature", DateTimeOffset.UtcNow.AddMinutes(5));
        }
        js.Release.TrySetResult();
        await obsolete.WaitAsync(TimeSpan.FromSeconds(5));
        if (replacement is not null) await replacement.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(change == "replace" ? "current.png" : null, GetField(page, "_selectedFile"));
        await page.DisposeAsync();
    }

    [Fact]
    public async Task LeavingFilesWhileLoading_DoesNotFetchOrPublishFilesFromTheAbandonedPage()
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        int fileRequests = 0;
        using var http = new HttpClient(new Handler(request =>
        {
            if (request.RequestUri!.AbsolutePath == "/api/v1/volumes") return pending.Task;
            fileRequests++;
            return Task.FromResult(Json(new { files = Array.Empty<object>() }));
        })) { BaseAddress = new Uri("http://test/") };
        var js = new NoopJs();
        using var auth = new WasmAuthStateProvider(js);
        await auth.SetTokenAsync("header.eyJzdWIiOiJhbGljZSJ9.signature", DateTimeOffset.UtcNow.AddMinutes(5));
        await using var crypto = new E2eeInterop(js);
        using var mounts = new ClientVolumeMountService(auth, crypto);
        var page = new CistaNAS.Wasm.Pages.Files { VolumeName = "volume" };
        Inject(page, "Auth", auth);
        Inject(page, "VolumeMountService", mounts);
        Inject(page, "VolumeApi", new VolumeApiClient(http));
        Inject(page, "FileApi", new FileApiClient(http));

        Task loading = (Task)typeof(CistaNAS.Wasm.Pages.Files)
            .GetMethod("OnInitializedAsync", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(page, null)!;
        await ((IAsyncDisposable)page).DisposeAsync();
        pending.SetResult(Json(new[] { new { name = "volume", encryptionMode = "server", ownerUser = "alice" } }));
        await loading.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, fileRequests);
    }

    private static void Inject(object page, string name, object value) => page.GetType()
        .GetProperty(name, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(page, value);
    private static void SetField(object page, string name, object value) => page.GetType()
        .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(page, value);
    private static object? GetField(object page, string name) => page.GetType()
        .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(page);
    private static Task InvokeTask(object page, string name, params object[] args) => (Task)page.GetType()
        .GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(page, args)!;
    private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK) { Content = JsonContent.Create(value) };
    private sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request);
    }
    private sealed class NoopJs : IJSRuntime
    {
        public ValueTask<T> InvokeAsync<T>(string identifier, object?[]? args) => ValueTask.FromResult(default(T)!);
        public ValueTask<T> InvokeAsync<T>(string identifier, CancellationToken ct, object?[]? args) => InvokeAsync<T>(identifier, args);
    }

    private sealed class PausedMediaJs : IJSRuntime
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<T> InvokeAsync<T>(string identifier, object?[]? args)
        {
            if (identifier == "cistaMedia.stop")
            { Entered.TrySetResult(); await Release.Task; }
            return default!;
        }
        public ValueTask<T> InvokeAsync<T>(string identifier, CancellationToken ct, object?[]? args) => InvokeAsync<T>(identifier, args);
    }
}
