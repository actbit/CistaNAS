using System.Net.Http.Json;
using System.Reflection;
using CistaNAS.Wasm.Auth;
using CistaNAS.Wasm.Services;
using Microsoft.JSInterop;

namespace CistaNAS.Tests;

public sealed class BrowserPageLifecycleTests
{
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
}
