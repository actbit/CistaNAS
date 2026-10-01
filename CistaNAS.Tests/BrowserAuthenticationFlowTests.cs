using System.Net.Http.Json;
using CistaNAS.Wasm.Auth;
using CistaNAS.Wasm.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace CistaNAS.Tests;

public sealed class BrowserAuthenticationFlowTests
{
    [Fact]
    public async Task InitialSetup_AuthenticatesBeforeCreatingTheRequestedVolume()
    {
        using var fixture = new Fixture(request => Task.FromResult(request.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/setup" => Json(new { }),
            "/api/v1/auth/login" => LoginResponse("alice"),
            "/api/v1/volumes" => request.Headers.Authorization?.Parameter == Token("alice")
                ? Json(new { name = "first" }) : new(HttpStatusCode.Unauthorized),
            _ => throw new InvalidOperationException()
        }));
        await fixture.Flow.SetupAsync("alice", "private-password", "first", fixture.Flow.Version, default);
        Assert.Equal(new[] { "/api/v1/auth/setup", "/api/v1/auth/login", "/api/v1/volumes" }, fixture.Paths);
        Assert.Equal("alice", fixture.Auth.CurrentUsername);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DelayedLogin_CannotAuthenticateAfterNavigationOrAnotherLogin(bool navigation)
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var fixture = new Fixture(_ => pending.Task);
        using var lifetime = new CancellationTokenSource();
        Task login = fixture.Flow.LoginAsync("alice", "private-password", fixture.Flow.Version, lifetime.Token);
        if (navigation) lifetime.Cancel();
        else await fixture.Auth.SetTokenAsync(Token("bob"), DateTimeOffset.UtcNow.AddMinutes(5));
        pending.SetResult(LoginResponse("alice"));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => login);
        Assert.Equal(navigation ? "" : "bob", fixture.Auth.CurrentUsername);
    }

    [Fact]
    public async Task SetupCancelledDuringAccountCreation_DoesNotStartLoginOrVolumeCreation()
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var fixture = new Fixture(_ => pending.Task);
        using var lifetime = new CancellationTokenSource();
        Task setup = fixture.Flow.SetupAsync("alice", "private-password", "first", fixture.Flow.Version, lifetime.Token);
        lifetime.Cancel();
        pending.SetResult(Json(new { }));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => setup);
        Assert.Equal(new[] { "/api/v1/auth/setup" }, fixture.Paths);
        Assert.False(fixture.Auth.IsLoggedIn);
    }

    private static string Token(string user) => "header." + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{{\"sub\":\"{user}\"}}")) + ".signature";
    private static HttpResponseMessage LoginResponse(string user) => Json(new { accessToken = Token(user), tokenType = "Bearer", expiresAt = DateTimeOffset.UtcNow.AddMinutes(5) });
    private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK) { Content = JsonContent.Create(value) };
    private sealed class Fixture : IDisposable
    {
        public WasmAuthStateProvider Auth { get; } = new(new NoopJs());
        public List<string> Paths { get; } = [];
        public BrowserAuthenticationService Flow { get; }
        private readonly HttpClient _http;
        public Fixture(Func<HttpRequestMessage, Task<HttpResponseMessage>> send)
        {
            var handler = new CistaNAS.Wasm.Services.HttpHandlers.AuthHeaderHandler(Auth, new Navigation())
            { InnerHandler = new Handler(request => { Paths.Add(request.RequestUri!.AbsolutePath); return send(request); }) };
            _http = new HttpClient(handler) { BaseAddress = new Uri("http://test/") };
            Flow = new(Auth, new AuthApiClient(_http), new VolumeApiClient(_http));
        }
        public void Dispose() { _http.Dispose(); Auth.Dispose(); }
    }
    private sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request);
    }
    private sealed class NoopJs : IJSRuntime
    {
        public ValueTask<T> InvokeAsync<T>(string identifier, object?[]? args) => ValueTask.FromResult(default(T)!);
        public ValueTask<T> InvokeAsync<T>(string identifier, CancellationToken ct, object?[]? args) => InvokeAsync<T>(identifier, args);
    }
    private sealed class Navigation : NavigationManager
    {
        public Navigation() => Initialize("http://test/", "http://test/");
        protected override void NavigateToCore(string uri, bool forceLoad) { }
    }
}
