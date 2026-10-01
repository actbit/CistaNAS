using CistaNAS.Wasm.Auth;
using CistaNAS.Wasm.Services;
using Microsoft.JSInterop;

namespace CistaNAS.Tests;

public sealed class BrowserMountLifecycleTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AuthenticationChange_ClearsMountedServerAndE2eeKeys(bool logout)
    {
        var js = new FakeJs();
        using var auth = new WasmAuthStateProvider(js);
        await using var crypto = new E2eeInterop(js);
        await Login(auth);
        using var mounts = CreateMounts(auth, crypto);
        byte[] master = Enumerable.Repeat((byte)7, 64).ToArray();
        mounts.MountServerEncrypted("server", master, "aes", 4096, 4096);
        mounts.MountE2ee("encrypted", "handle", 4096, "group-e2ee", "volume", new Dictionary<int, string> { [1] = "secret" });
        var borrowed = mounts.GetE2eeV2Keys("encrypted")!.Value.GroupKeys;
        if (logout) await auth.LogoutAsync(); else await Login(auth);
        Assert.Empty(mounts.MountedVolumes);
        Assert.All(master, b => Assert.Equal(0, b));
        Assert.Empty(borrowed);
        Assert.Contains("handle", js.Cleared);
    }

    [Fact]
    public async Task LogoutClearsKeysBeforeSessionStorageCompletes()
    {
        var js = new FakeJs();
        using var auth = new WasmAuthStateProvider(js);
        await using var crypto = new E2eeInterop(js);
        await Login(auth);
        using var mounts = CreateMounts(auth, crypto);
        mounts.MountE2ee("encrypted", "handle", 4096, "e2ee");
        js.PauseRemoval = true;
        Task logout = auth.LogoutAsync();
        try { Assert.False(mounts.IsMounted("encrypted")); }
        finally { js.Removal.TrySetResult(); await logout.WaitAsync(TimeSpan.FromSeconds(5)); }
    }

    [Fact]
    public async Task ReplacingMount_ErasesPreviousMasterKey()
    {
        var js = new FakeJs();
        using var auth = new WasmAuthStateProvider(js);
        await using var crypto = new E2eeInterop(js);
        await Login(auth);
        using var mounts = CreateMounts(auth, crypto);
        byte[] first = Enumerable.Repeat((byte)7, 64).ToArray(), second = Enumerable.Repeat((byte)9, 64).ToArray();
        mounts.MountServerEncrypted("server", first, "aes", 4096, 4096);
        mounts.MountServerEncrypted("server", second, "aes", 4096, 4096);
        Assert.All(first, b => Assert.Equal(0, b));
        Assert.Same(second, mounts.GetMasterKey("server"));
        Assert.All(second, b => Assert.Equal(9, b));
    }

    [Fact]
    public async Task LockClearsBorrowedGroupKeysAndTheJavascriptHandle()
    {
        var js = new FakeJs();
        using var auth = new WasmAuthStateProvider(js);
        await using var crypto = new E2eeInterop(js);
        await Login(auth);
        using var mounts = CreateMounts(auth, crypto);
        mounts.MountE2ee("encrypted", "handle", 4096, "group-e2ee", "volume", new Dictionary<int, string> { [1] = "secret" });
        var borrowed = mounts.GetE2eeV2Keys("encrypted")!.Value.GroupKeys;
        mounts.Lock("encrypted");
        Assert.Empty(borrowed);
        Assert.Contains("handle", js.Cleared);
    }

    private static Task Login(WasmAuthStateProvider auth) => auth.SetTokenAsync(
        "header." + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{\"sub\":\"alice\"}")) + ".signature", DateTimeOffset.UtcNow.AddMinutes(5));

    private static ClientVolumeMountService CreateMounts(WasmAuthStateProvider auth, E2eeInterop crypto)
        => new(auth, crypto);

    [Fact]
    public async Task OlderUnlockCannotPublishKeysAfterAnotherLogin()
    {
        var js = new FakeJs();
        using var auth = new WasmAuthStateProvider(js);
        await using var crypto = new E2eeInterop(js);
        await Login(auth);
        using var mounts = CreateMounts(auth, crypto);
        long version = mounts.CaptureSession();
        await auth.LogoutAsync();
        await Login(auth);
        Assert.ThrowsAny<OperationCanceledException>(() => mounts.MountE2ee("encrypted", "old-handle", 4096, "e2ee", version));
        Assert.False(mounts.IsMounted("encrypted"));
    }

    private sealed class FakeJs : IJSRuntime, IJSObjectReference
    {
        public List<string> Cleared { get; } = [];
        public bool PauseRemoval;
        public TaskCompletionSource Removal { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ValueTask<T> InvokeAsync<T>(string identifier, object?[]? args) => InvokeAsync<T>(identifier, default, args);
        public async ValueTask<T> InvokeAsync<T>(string identifier, CancellationToken ct, object?[]? args)
        {
            if (identifier == "import") return (T)(object)this;
            if (identifier == "clearKey") Cleared.Add((string)args![0]!);
            if (PauseRemoval && identifier == "sessionStorage.removeItem") await Removal.Task.WaitAsync(ct);
            return default!;
        }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
