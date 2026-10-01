using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using CistaNAS.Client;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;
using CistaNAS.Mobile.Core.ViewModels;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

public sealed class ClientReadIntegrityRegressionTests
{
    [Fact]
    public async Task LogoutWhileServerMountIsPending_DoesNotNavigateIntoClearedSession()
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var app = CreateApp(new Handler((_, _) => pending.Task));
        var vm = new VolumesViewModel(app);
        vm.OpenVolumeCommand.Execute(new VolumeListItem { Name = "vol", EncryptionMode = "server", IsMounted = false });
        vm.MountPassword = "password";
        Task mount = vm.ConfirmMountCommand.ExecuteAsync(null);
        app.ClearSession();
        pending.TrySetResult(new HttpResponseMessage(HttpStatusCode.OK));
        await mount.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Null(app.Navigation.Current);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LogoutWhileUnlockIsPending_DoesNotRestoreKeysOrNavigate(bool alreadyMounted)
    {
        byte[] master = E2eeCrypto.GenerateMasterKey(), salt = E2eeCrypto.GenerateFileSalt();
        byte[] kek = E2eeCrypto.DeriveKek("alice", "password", salt, 1000);
        var (nonce, ciphertext, tag) = E2eeCrypto.WrapMasterKey(master, kek);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(master);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(kek);
        string wrapped = JsonSerializer.Serialize(new
        {
            kdf = new { algorithm = "pbkdf2-sha256", iterations = 1000, salt },
            wrappedMasterKey = new { nonce, ciphertext, tag }, chunkSize = 4096
        });
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var app = CreateApp(new Handler((request, _) =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("group-key-info"))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            bool keyRequest = request.Method == HttpMethod.Get;
            if (keyRequest == alreadyMounted) { reached.TrySetResult(); return pending.Task; }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent(wrapped, Encoding.UTF8, "application/json") });
        }));
        app.Settings.Username = "alice";
        var vm = new VolumesViewModel(app);
        vm.OpenVolumeCommand.Execute(new VolumeListItem { Name = "vol", EncryptionMode = "e2ee", IsMounted = alreadyMounted });
        vm.MountPassword = "password";
        Task mount = vm.ConfirmMountCommand.ExecuteAsync(null);
        try
        {
            await reached.Task.WaitAsync(TimeSpan.FromSeconds(5));
            app.ClearSession();
        }
        finally
        {
            pending.TrySetResult(new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent(wrapped, Encoding.UTF8, "application/json") });
            await mount.WaitAsync(TimeSpan.FromSeconds(5));
        }
        Assert.False(app.E2ee.HasKey("vol"));
        Assert.False(app.E2ee.HasV2State("vol"));
        Assert.Null(app.Navigation.Current);
    }

    [Fact]
    public async Task RequiredRange_RangeNotSatisfiableIsAnError()
    {
        using var http = new HttpClient(new Handler((_, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.RequestedRangeNotSatisfiable)))) { BaseAddress = new Uri("http://test/") };
        await Assert.ThrowsAsync<EndOfStreamException>(() => new CistaNasApiClient(http)
            .DownloadFileRangeAsync("vol", "file.txt", 0, 5, requireExactRange: true));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TruncationOrExtension_ShortRangeMustNotOverwriteMissingBytesWithZeros(bool extend)
    {
        int uploads = 0;
        using var http = new HttpClient(new Handler((request, _) =>
        {
            if (request.Method == HttpMethod.Get)
            {
                long end = request.Headers.Range!.Ranges.Single().To!.Value;
                var response = new HttpResponseMessage(HttpStatusCode.PartialContent) { Content = new ByteArrayContent([1, 2]) };
                response.Content.Headers.ContentRange = new ContentRangeHeaderValue(0, end, 10);
                return Task.FromResult(response);
            }
            uploads++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent("{\"name\":\"file.txt\",\"length\":5,\"createdAt\":\"2026-01-01T00:00:00Z\",\"modifiedAt\":\"2026-01-01T00:00:00Z\"}", Encoding.UTF8, "application/json") });
        })) { BaseAddress = new Uri("http://test/") };
        using var fs = new CistaNasFileSystem(new CistaNasApiClient(http), "vol");
        var state = new CistaNasFileSystem.PlainRangeWriteState(fs, "file.txt", "file.txt", existingLength: 10);
        try
        {
            state.SetDeclaredSize(extend ? 15 : 5);
            Assert.ThrowsAny<IOException>(() => fs.UploadWriteState(state));
            Assert.Equal(0, uploads);
            Assert.True(state.HasPending);
        }
        finally { state.Dispose(); }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ImageOrText_ClosingOrLogoutClearsLoadedPlaintext(bool image, bool logout)
    {
        using var app = CreateApp(new Handler((request, _) => Task.FromResult(Response(request, "secret"u8.ToArray()))));
        var vm = CreateViewer(app, image, 6);
        try
        {
            vm.OnNavigatedTo();
            await WaitUntilIdle(vm);
            byte[]? heldImage = (vm as ImageViewerViewModel)?.ImageData;
            if (logout) app.ClearSession(); else vm.OnNavigatedFrom();
            if (image)
            {
                Assert.Null(((ImageViewerViewModel)vm).ImageData);
                Assert.All(heldImage!, b => Assert.Equal(0, b));
            }
            else Assert.Equal("", ((TextViewerViewModel)vm).Content);
        }
        finally { (vm as IDisposable)?.Dispose(); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ImageOrText_NavigationCancelsPendingDownloadAndRejectsLateResult(bool image)
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        HttpRequestMessage? observed = null;
        CancellationToken download = default;
        using var app = CreateApp(new Handler((request, ct) => { observed = request; download = ct; return pending.Task; }));
        var vm = CreateViewer(app, image, 6);
        try
        {
            vm.OnNavigatedTo();
            Assert.NotNull(observed);
            vm.OnNavigatedFrom();
            Assert.True(download.IsCancellationRequested);
        }
        finally
        {
            pending.TrySetResult(Response(observed!, "secret"u8.ToArray()));
            await WaitUntilIdle(vm);
            (vm as IDisposable)?.Dispose();
        }
        if (image) Assert.Null(((ImageViewerViewModel)vm).ImageData);
        else Assert.Equal("", ((TextViewerViewModel)vm).Content);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OversizedServerPreview_IsRejectedBeforeStartingDownload(bool image)
    {
        int requests = 0;
        using var app = CreateApp(new Handler((request, _) => { requests++; return Task.FromResult(Response(request, [1])); }));
        var vm = CreateViewer(app, image, 60 * 1024 * 1024);
        try
        {
            vm.OnNavigatedTo();
            await WaitUntilIdle(vm);
            Assert.NotNull(vm.Error);
            Assert.Equal(0, requests);
        }
        finally { (vm as IDisposable)?.Dispose(); }
    }

    private static BusyViewModelBase CreateViewer(AppServices app, bool image, long length)
    {
        string name = image ? "photo.png" : "text.txt";
        var browser = new FileBrowserViewModel(app, new VolumeListItem { Name = "vol", EncryptionMode = "server" });
        var item = new FileItem { Name = name, FullPath = name, IsFolder = false, ServerMeta = new FileMetadata { Name = name, Length = length } };
        return image ? new ImageViewerViewModel(app, browser, item) : new TextViewerViewModel(app, browser, item);
    }
    private static AppServices CreateApp(HttpMessageHandler handler)
    {
        var app = new AppServices(new MemorySecureKeyStore(), new MemoryAppSettings(), new RecordingFileViewer(), handler);
        app.Session.ConfigureServer("http://test/");
        return app;
    }
    private static HttpResponseMessage Response(HttpRequestMessage request, byte[] bytes)
    {
        var response = new HttpResponseMessage(HttpStatusCode.PartialContent) { Content = new ByteArrayContent(bytes) };
        var range = request.Headers.Range?.Ranges.Single();
        response.Content.Headers.ContentRange = new ContentRangeHeaderValue(range?.From ?? 0, range?.To ?? bytes.Length - 1, Math.Max(bytes.Length, (range?.To ?? 0) + 1));
        return response;
    }
    private static async Task WaitUntilIdle(BusyViewModelBase vm)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (vm.IsBusy) await Task.Delay(10, timeout.Token);
    }
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request, ct);
    }
}
