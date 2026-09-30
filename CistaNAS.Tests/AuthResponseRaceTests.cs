using System.Net.Http.Headers;
using CistaNAS.Mobile.Core.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace CistaNAS.Tests;

public sealed class AuthResponseRaceTests
{
    [Theory]
    [InlineData(false, true, false)]
    [InlineData(true, true, false)]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    public async Task BrowserUnauthorized_OnlyExpiresTheAuthenticationThatSentTheRequest(bool initiallyLoggedIn, bool changed, bool sameToken)
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var auth = new CistaNAS.Wasm.Auth.WasmAuthStateProvider(new NoopJs());
        var navigation = new TestNavigation();
        using var handler = new CistaNAS.Wasm.Services.HttpHandlers.AuthHeaderHandler(auth, navigation)
        { InnerHandler = new Handler((_, _) => pending.Task) };
        using var http = new HttpClient(handler);
        string Token(string user) => "header." + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{\"sub\":\"" + user + "\"}")) + ".signature";
        if (initiallyLoggedIn) await auth.SetTokenAsync(Token("old"), DateTimeOffset.UtcNow.AddMinutes(5));
        Task<HttpResponseMessage> request = http.GetAsync("http://test/api");
        if (changed) await auth.SetTokenAsync(Token(sameToken ? "old" : "new"), DateTimeOffset.UtcNow.AddMinutes(5));
        pending.SetResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));
        using var response = await request;
        Assert.Equal(changed, auth.IsLoggedIn);
        Assert.Equal(changed ? 0 : 1, navigation.Redirects);
    }

    [Theory]
    [InlineData("login")]
    [InlineData("logout")]
    [InlineData("server")]
    [InlineData("same_token")]
    public async Task OldUnauthorizedResponse_DoesNotInvalidateChangedAuthentication(string change)
    {
        var pending = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var session = new ApiSession(new Handler((_, _) => pending.Task));
        session.ConfigureServer("http://first/");
        session.SetToken("old-token");
        int expired = 0;
        session.Unauthorized += () => { expired++; session.ClearToken(); };
        Task request = session.Api.LoginAsync("user", "password");
        if (change == "server") session.ConfigureServer("http://second/");
        if (change == "logout") session.ClearToken(); else session.SetToken(change == "same_token" ? "old-token" : "new-token");
        pending.SetResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));
        await Assert.ThrowsAsync<HttpRequestException>(() => request);
        Assert.Equal(0, expired);
    }

    [Fact]
    public async Task ClearedToken_RemovesAuthorizationAlreadyPresentOnRequest()
    {
        string? sent = "not-observed";
        using var auth = new AuthHeaderHandler(() => null, () => new Uri("http://second/"))
        {
            InnerHandler = new Handler((request, _) =>
            { sent = request.Headers.Authorization?.ToString(); return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)); })
        };
        using var http = new HttpClient(auth);
        using var request = new HttpRequestMessage(HttpMethod.Get, "http://first/test");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "previous-server-token");
        using var response = await http.SendAsync(request);
        Assert.Null(sent);
    }

    [Fact]
    public async Task CurrentUnauthorizedResponse_StillExpiresAuthentication()
    {
        using var session = new ApiSession(new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized))));
        session.ConfigureServer("http://first/");
        session.SetToken("current-token");
        int expired = 0;
        session.Unauthorized += () => expired++;
        await Assert.ThrowsAsync<HttpRequestException>(() => session.Api.LoginAsync("user", "password"));
        Assert.Equal(1, expired);
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request, ct);
    }
    private sealed class NoopJs : IJSRuntime
    {
        public ValueTask<T> InvokeAsync<T>(string identifier, object?[]? args) => ValueTask.FromResult(default(T)!);
        public ValueTask<T> InvokeAsync<T>(string identifier, CancellationToken ct, object?[]? args) => InvokeAsync<T>(identifier, args);
    }
    private sealed class TestNavigation : NavigationManager
    {
        public int Redirects;
        public TestNavigation() => Initialize("http://test/", "http://test/");
        protected override void NavigateToCore(string uri, bool forceLoad) => Redirects++;
    }
}
