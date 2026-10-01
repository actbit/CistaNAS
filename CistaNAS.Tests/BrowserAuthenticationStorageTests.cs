using CistaNAS.Wasm.Auth;
using Microsoft.JSInterop;

namespace CistaNAS.Tests;

public sealed class BrowserAuthenticationStorageTests
{
    [Fact]
    public async Task Logout_NotifiesTheVisiblePageBeforeStorageRemovalCompletes()
    {
        var js = new Storage();
        using var auth = new WasmAuthStateProvider(js);
        await Login(auth, "alice");
        bool notified = false;
        auth.StateChanged += () => notified = !auth.IsLoggedIn;
        js.Pause("sessionStorage.removeItem", "cista_jwt");
        Task logout = auth.LogoutAsync();
        try { Assert.True(notified); }
        finally { js.Release.TrySetResult(); await logout.WaitAsync(TimeSpan.FromSeconds(5)); }
    }

    [Fact]
    public async Task LoginStorageFinishingAfterLogout_DoesNotRestoreTheRemovedToken()
    {
        var js = new Storage();
        using var auth = new WasmAuthStateProvider(js);
        js.Pause("sessionStorage.setItem", "cista_jwt");
        Task login = Login(auth, "alice");
        await js.Reached.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Task logout = auth.LogoutAsync();
        Assert.False(auth.IsLoggedIn);
        js.Release.SetResult();
        await Task.WhenAll(login, logout).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Null(js.Get("cista_jwt"));
        Assert.Null(js.Get("cista_jwt_expires"));
        using var restored = new WasmAuthStateProvider(js);
        await restored.TryRestoreAsync();
        Assert.False(restored.IsLoggedIn);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task OlderStorageMutation_CannotRemoveOrOverwriteANewerLogin(bool logout)
    {
        var js = new Storage();
        using var auth = new WasmAuthStateProvider(js);
        await Login(auth, "alice");
        js.Pause(logout ? "sessionStorage.removeItem" : "sessionStorage.setItem", "cista_jwt");
        Task older = logout ? auth.LogoutAsync() : Login(auth, "older");
        await js.Reached.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Task newer = Login(auth, "bob");
        js.Release.SetResult();
        await Task.WhenAll(older, newer).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("bob", auth.CurrentUsername);
        Assert.Equal(auth.Token, js.Get("cista_jwt"));
        using var restored = new WasmAuthStateProvider(js);
        await restored.TryRestoreAsync();
        Assert.Equal("bob", restored.CurrentUsername);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DelayedRestore_CannotOverwriteLogoutOrANewLogin(bool login)
    {
        var js = new Storage();
        using (var initial = new WasmAuthStateProvider(js)) await Login(initial, "alice");
        using var auth = new WasmAuthStateProvider(js);
        js.Pause("sessionStorage.getItem", "cista_jwt_expires");
        Task restore = auth.TryRestoreAsync();
        await js.Reached.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Task newer = login ? Login(auth, "bob") : auth.LogoutAsync();
        js.Release.SetResult();
        await Task.WhenAll(restore, newer).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(login, auth.IsLoggedIn);
        Assert.Equal(login ? "bob" : "", auth.CurrentUsername);
    }

    private static Task Login(WasmAuthStateProvider auth, string username) => auth.SetTokenAsync(
        "header." + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{{\"sub\":\"{username}\"}}")) + ".signature",
        DateTimeOffset.UtcNow.AddMinutes(5));

    private sealed class Storage : IJSRuntime
    {
        private readonly Dictionary<string, string> _values = [];
        private (string Identifier, string Key)? _pause;
        public TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void Pause(string identifier, string key) => _pause = (identifier, key);
        public string? Get(string key) => _values.GetValueOrDefault(key);
        public ValueTask<T> InvokeAsync<T>(string identifier, object?[]? args) => InvokeAsync<T>(identifier, default, args);
        public async ValueTask<T> InvokeAsync<T>(string identifier, CancellationToken ct, object?[]? args)
        {
            string key = (string)args![0]!;
            string? captured = Get(key);
            if (_pause == (identifier, key))
            {
                _pause = null;
                Reached.TrySetResult();
                await Release.Task.WaitAsync(ct);
            }
            if (identifier == "sessionStorage.setItem") _values[key] = (string)args[1]!;
            if (identifier == "sessionStorage.removeItem") _values.Remove(key);
            return identifier == "sessionStorage.getItem" ? (T)(object?)captured! : default!;
        }
    }
}
