using System.Net.Http.Json;
using System.Text.Json;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;
using CistaNAS.Mobile.Core.ViewModels;

namespace CistaNAS.Tests;

public sealed class MobileAuthenticationLifecycleTests
{
    [Fact]
    public async Task RejectedLogin_ShowsTheCredentialErrorWithoutExpiringAnAnonymousSession()
    {
        using var app = CreateApp(new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized))));
        int expired = 0;
        app.SessionExpired += () => expired++;
        var login = new LoginViewModel(app) { Username = "alice", Password = "incorrect" };
        app.Navigation.NavigateToRoot(login);
        await login.LoginCommand.ExecuteAsync(null);
        Assert.Equal("ユーザー名またはパスワードが違います。", login.Error);
        Assert.Same(login, app.Navigation.Current);
        Assert.Equal(0, expired);
    }

    [Theory]
    [InlineData("logout")]
    [InlineData("server")]
    [InlineData("direct_server")]
    [InlineData("navigation")]
    [InlineData("cancel")]
    [InlineData("new_login")]
    public async Task DelayedLogin_CannotPublishIntoAnotherSessionOrScreen(string change)
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        string? sentToken = null;
        using var app = CreateApp(new Handler((request, _) =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/login")) return pending.Task;
            sentToken = request.Headers.Authorization?.Parameter;
            return Task.FromResult(Json(new { hasUsers = true }));
        }));
        var login = new LoginViewModel(app) { Username = "alice", Password = "private-password" };
        app.Navigation.NavigateToRoot(login);
        Task operation = login.LoginCommand.ExecuteAsync(null);
        if (change is "logout" or "server") app.ClearSession();
        if (change is "server" or "direct_server") app.Session.ConfigureServer("http://second/");
        if (change == "navigation") app.Navigation.NavigateToRoot(new Marker());
        if (change == "cancel") login.LoginCommand.Cancel();
        if (change == "new_login") app.Session.SetToken("new-token");
        ViewModelBase? current = app.Navigation.Current;
        pending.SetResult(Json(new { accessToken = "old-server-token" }));
        await operation.WaitAsync(TimeSpan.FromSeconds(5));
        await app.Session.Api.HasUsersAsync();
        Assert.Equal(change == "new_login" ? "new-token" : null, sentToken);
        Assert.Equal("initial", app.Settings.Username);
        Assert.Equal(0, ((MemoryAppSettings)app.Settings).SaveCount);
        Assert.Same(current, app.Navigation.Current);
    }

    [Fact]
    public async Task SuccessfulLogin_UsesSubmittedUsernameEvenIfFormChanges()
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var app = CreateApp(new Handler((request, _) => request.Method == HttpMethod.Post
            ? pending.Task : Task.FromResult(Json(new { volumes = Array.Empty<object>() }))));
        var login = new LoginViewModel(app) { Username = "alice", Password = "private-password" };
        app.Navigation.NavigateToRoot(login);
        Task operation = login.LoginCommand.ExecuteAsync(null);
        login.Username = "bob";
        pending.SetResult(Json(new { accessToken = "alice-token" }));
        await operation.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("alice", app.Settings.Username);
        Assert.IsType<VolumesViewModel>(app.Navigation.Current);
        Assert.Equal("", login.Password);
    }

    [Theory]
    [InlineData("logout")]
    [InlineData("server")]
    [InlineData("navigation")]
    [InlineData("cancel")]
    public async Task SetupCannotSendItsFollowupPasswordAfterTheOperationEnds(string change)
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        int loginRequests = 0;
        using var app = CreateApp(new Handler((request, _) =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/setup")) return pending.Task;
            if (request.RequestUri.AbsolutePath.EndsWith("/login")) loginRequests++;
            return Task.FromResult(Json(new { accessToken = "token", volumes = Array.Empty<object>() }));
        }));
        var setup = new SetupViewModel(app) { Username = "alice", Password = "private-password", PasswordConfirm = "private-password" };
        app.Navigation.NavigateToRoot(setup);
        Task operation = setup.SetupCommand.ExecuteAsync(null);
        if (change == "logout") app.ClearSession();
        if (change == "server") app.Session.ConfigureServer("http://second/");
        if (change == "navigation") app.Navigation.NavigateToRoot(new Marker());
        if (change == "cancel") setup.SetupCommand.Cancel();
        ViewModelBase? current = app.Navigation.Current;
        pending.SetResult(new HttpResponseMessage(HttpStatusCode.NoContent));
        await operation.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, loginRequests);
        Assert.Same(current, app.Navigation.Current);
        Assert.Equal(0, ((MemoryAppSettings)app.Settings).SaveCount);
    }

    [Fact]
    public async Task SetupFollowupLogin_UsesTheCredentialsActuallyCreated()
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        JsonElement submitted = default;
        using var app = CreateApp(new Handler(async (request, ct) =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/setup")) return await pending.Task;
            if (request.RequestUri.AbsolutePath.EndsWith("/login")) submitted = await request.Content!.ReadFromJsonAsync<JsonElement>(ct);
            return Json(new { accessToken = "alice-token", volumes = Array.Empty<object>() });
        }));
        var setup = new SetupViewModel(app) { Username = "alice", Password = "private-password", PasswordConfirm = "private-password" };
        app.Navigation.NavigateToRoot(setup);
        Task operation = setup.SetupCommand.ExecuteAsync(null);
        setup.Username = "bob"; setup.Password = setup.PasswordConfirm = "other-password";
        pending.SetResult(new HttpResponseMessage(HttpStatusCode.NoContent));
        await operation.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("alice", submitted.GetProperty("username").GetString());
        Assert.Equal("private-password", submitted.GetProperty("password").GetString());
        Assert.Equal("alice", app.Settings.Username);
        Assert.Equal("", setup.Password);
        Assert.Equal("", setup.PasswordConfirm);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ConnectResponse_UsesTheSubmittedAddressAndCannotNavigateAfterLeaving(bool leave)
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var app = CreateApp(new Handler((_, _) => pending.Task));
        var connect = new ConnectViewModel(app) { ServerUrl = "http://first/" };
        app.Navigation.NavigateToRoot(connect);
        Task operation = connect.ConnectCommand.ExecuteAsync(null);
        connect.ServerUrl = "http://second/";
        if (leave) app.Navigation.NavigateToRoot(new Marker());
        ViewModelBase? current = app.Navigation.Current;
        pending.SetResult(Json(new { hasUsers = true }));
        await operation.WaitAsync(TimeSpan.FromSeconds(5));
        if (leave)
        {
            Assert.Same(current, app.Navigation.Current);
            Assert.Equal(0, ((MemoryAppSettings)app.Settings).SaveCount);
        }
        else
        {
            Assert.Equal("http://first", app.Settings.ServerUrl);
            Assert.IsType<LoginViewModel>(app.Navigation.Current);
        }
    }

    private static AppServices CreateApp(HttpMessageHandler handler)
    {
        var app = new AppServices(new MemorySecureKeyStore(), new MemoryAppSettings { Username = "initial" }, new RecordingFileViewer(), handler);
        app.Session.ConfigureServer("http://first/");
        return app;
    }
    private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK) { Content = JsonContent.Create(value) };
    private sealed class Marker : ViewModelBase;
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request, ct);
    }
}
