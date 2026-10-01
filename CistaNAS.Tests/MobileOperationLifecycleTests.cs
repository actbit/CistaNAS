using System.Net.Http.Json;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;
using CistaNAS.Mobile.Core.ViewModels;

namespace CistaNAS.Tests;

public sealed class MobileOperationLifecycleTests
{
    [Fact]
    public async Task ReturningToBrowser_StartsAFreshLoadWithoutWaitingForAnAbandonedRequest()
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        int requests = 0;
        using var app = CreateApp(new Handler(_ => ++requests == 2 ? pending.Task : Task.FromResult(FileList("current.txt"))));
        var vm = new FileBrowserViewModel(app, new VolumeListItem { Name = "vol", EncryptionMode = "server" });
        app.Navigation.NavigateToRoot(vm);
        Task older = vm.RefreshCommand.ExecuteAsync(null);
        app.Navigation.NavigateTo(new Marker());
        app.Navigation.GoBack();
        Assert.Equal(3, requests);
        Assert.Equal("current.txt", Assert.Single(vm.Items).Name);
        pending.SetResult(FileList("abandoned.txt"));
        await older.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("current.txt", Assert.Single(vm.Items).Name);
    }

    private static HttpResponseMessage FileList(string name) => Json(new { files = new[] { new { name,
        length = 1, createdAt = DateTimeOffset.UtcNow, modifiedAt = DateTimeOffset.UtcNow } } });

    [Theory]
    [InlineData("cancel")]
    [InlineData("navigation")]
    [InlineData("server")]
    public async Task DelayedMount_CannotNavigateAfterCancellationOrSessionChange(string change)
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var app = CreateApp(new Handler(request => request.Method == HttpMethod.Post
            ? pending.Task : Task.FromResult(Json(Array.Empty<object>()))));
        var vm = new VolumesViewModel(app);
        app.Navigation.NavigateToRoot(vm);
        vm.OpenVolumeCommand.Execute(new VolumeListItem { Name = "vol", EncryptionMode = "server" });
        vm.MountPassword = "private-password";
        Task mount = vm.ConfirmMountCommand.ExecuteAsync(null);
        if (change == "cancel") vm.CancelMountCommand.Execute(null);
        if (change == "navigation") app.Navigation.NavigateToRoot(new Marker());
        if (change == "server") app.Session.ConfigureServer("http://second/");
        ViewModelBase? expected = app.Navigation.Current;
        pending.SetResult(Json(new { name = "vol" }));
        await mount.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Same(expected, app.Navigation.Current);
        Assert.False(vm.IsMountPromptVisible);
        Assert.Equal("", vm.MountPassword);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CancelMount_HidesThePromptAndErasesBothPasswords(bool confirm)
    {
        using var app = CreateApp(new Handler(_ => Task.FromResult(Json(Array.Empty<object>()))));
        var vm = new VolumesViewModel(app);
        vm.OpenVolumeCommand.Execute(new VolumeListItem { Name = "vol", EncryptionMode = "e2ee" });
        vm.MountPassword = vm.MountE2eePassword = "private-password";
        vm.CancelMountCommand.Execute(null);
        if (confirm) await vm.ConfirmMountCommand.ExecuteAsync(null);
        Assert.False(vm.IsMountPromptVisible);
        Assert.Equal("", vm.MountPassword);
        Assert.Equal("", vm.MountE2eePassword);
    }

    [Theory]
    [InlineData("navigation")]
    [InlineData("cancel")]
    public async Task DelayedCreate_CannotPopAReplacementScreen(string change)
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var app = CreateApp(new Handler(_ => pending.Task));
        app.Navigation.NavigateToRoot(new Marker());
        var vm = new CreateVolumeViewModel(app) { IsE2ee = false, VolumeName = "vol", Password = "private-password", PasswordConfirm = "private-password" };
        app.Navigation.NavigateTo(vm);
        Task create = vm.CreateCommand.ExecuteAsync(null);
        if (change == "cancel") vm.CreateCommand.Cancel();
        else { app.Navigation.GoBack(); app.Navigation.NavigateTo(new Marker()); }
        ViewModelBase? expected = app.Navigation.Current;
        pending.SetResult(Json(new { name = "vol" }));
        await create.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Same(expected, app.Navigation.Current);
    }

    [Theory]
    [InlineData("server")]
    [InlineData("login")]
    [InlineData("cancel")]
    [InlineData("navigation")]
    public async Task CreateAfterDelayedSettings_CannotSendToAnotherSessionOrAbandonedScreen(string change)
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        int creates = 0;
        using var app = CreateApp(new Handler(request =>
        {
            if (request.Method == HttpMethod.Get) return pending.Task;
            creates++;
            return Task.FromResult(Json(new { name = "vol" }));
        }));
        app.Navigation.NavigateToRoot(new Marker());
        var vm = new CreateVolumeViewModel(app) { VolumeName = "vol", Password = "private-password", PasswordConfirm = "private-password" };
        app.Navigation.NavigateTo(vm);
        Task create = vm.CreateCommand.ExecuteAsync(null);
        if (change == "server") app.Session.ConfigureServer("http://second/");
        if (change == "login") app.Session.SetToken("bob-token");
        if (change == "cancel") vm.CreateCommand.Cancel();
        if (change == "navigation") app.Navigation.GoBack();
        pending.SetResult(Json(new { defaultEncryptionMode = "e2ee", e2eeChunkSize = 4096,
            kdfAlgorithm = "argon2id-raw", kdfIterations = 0, kdfMemoryKiB = 32, kdfTimeCost = 1, kdfParallelism = 1, sectorSize = 4096 }));
        await create.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, creates);
    }

    [Theory]
    [InlineData(true, "navigation")]
    [InlineData(true, "logout")]
    [InlineData(true, "cancel")]
    [InlineData(false, "navigation")]
    [InlineData(false, "logout")]
    [InlineData(false, "cancel")]
    public async Task DelayedLists_CannotRepopulateAbandonedOrCancelledScreens(bool files, string change)
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        bool delay = false;
        using var app = CreateApp(new Handler(_ => delay ? pending.Task : Task.FromResult(files
            ? Json(new { files = Array.Empty<object>() }) : Json(Array.Empty<object>()))));
        BusyViewModelBase vm = files
            ? new FileBrowserViewModel(app, new VolumeListItem { Name = "vol", EncryptionMode = "server" })
            : new VolumesViewModel(app);
        app.Navigation.NavigateToRoot(vm);
        delay = true;
        Task load = files ? ((FileBrowserViewModel)vm).RefreshCommand.ExecuteAsync(null) : ((VolumesViewModel)vm).RefreshCommand.ExecuteAsync(null);
        if (change == "navigation") app.Navigation.NavigateToRoot(new Marker());
        if (change == "logout") { app.ClearSession(); app.Navigation.NavigateToRoot(new Marker()); }
        if (change == "cancel")
        {
            if (files) ((FileBrowserViewModel)vm).RefreshCommand.Cancel(); else ((VolumesViewModel)vm).RefreshCommand.Cancel();
        }
        pending.SetResult(files ? Json(new { files = new[] { new { name = "private.txt", length = 1,
            createdAt = DateTimeOffset.UtcNow, modifiedAt = DateTimeOffset.UtcNow } } }) : Json(new[] { new { name = "private-volume" } }));
        await load.WaitAsync(TimeSpan.FromSeconds(5));
        if (files) Assert.Empty(((FileBrowserViewModel)vm).Items); else Assert.Empty(((VolumesViewModel)vm).Volumes);
    }

    private static AppServices CreateApp(HttpMessageHandler handler)
    {
        var app = new AppServices(new MemorySecureKeyStore(), new MemoryAppSettings { Username = "alice" }, new RecordingFileViewer(), handler);
        app.Session.ConfigureServer("http://first/");
        app.Session.SetToken("alice-token");
        return app;
    }
    private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK) { Content = JsonContent.Create(value) };
    private sealed class Marker : ViewModelBase;
    private sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request);
    }
}
