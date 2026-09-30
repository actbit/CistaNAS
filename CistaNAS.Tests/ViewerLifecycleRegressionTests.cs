using System.Text;
using CistaNAS.Client.Services;
using CistaNAS.Client.ViewModels;
using CistaNAS.Mobile.Core.Services;
using SecureBuffer = CistaNAS.Client.Security.SecureBuffer;

namespace CistaNAS.Tests;

public sealed class ViewerLifecycleRegressionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OldFolderListing_CannotReplaceNewerFolderOrErrorStatus(bool oldRequestFails)
    {
        var pending = new TaskCompletionSource<PreviewEntry[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var opened = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var vm = new FilePreviewViewModel(new Listings((relative, _) =>
        {
            if (relative == "older") { opened.TrySetResult(); return pending.Task; }
            return Task.FromResult(new[] { new PreviewEntry("current.txt", "current.txt", false) });
        }));
        vm.SelectedItem = new PreviewEntry("older", "older", true);
        Task old = vm.OpenCommand.ExecuteAsync(null);
        await opened.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await vm.UpCommand.ExecuteAsync(null);
        if (oldRequestFails) pending.SetException(new IOException("stale error"));
        else pending.SetResult([new PreviewEntry("stale.txt", "older/stale.txt", false)]);
        await old;
        Assert.Equal("/", vm.Location);
        Assert.Equal("current.txt", Assert.Single(vm.Items).Name);
        Assert.Equal("画像・テキストを選択してください。", vm.Status);
    }

    [Fact]
    public async Task SlowDokanOpen_DoesNotBlockTheCallingUiThread()
    {
        using var release = new ManualResetEventSlim();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var returned = new TaskCompletionSource<Task<SecureBuffer>>(TaskCreationOptions.RunContinuationsAsynchronously);
        var service = new MountedFilePreviewService("X:\\", _ =>
        {
            started.TrySetResult();
            if (!release.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException();
            return new MemoryStream(new byte[] { 42 });
        });
        var ui = new Thread(() =>
        {
            try { returned.TrySetResult(service.ReadAsync("secret.txt", default)); }
            catch (Exception ex) { returned.TrySetException(ex); }
        }) { IsBackground = true };
        ui.Start();
        try
        {
            await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Task<SecureBuffer> reading = await returned.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(reading.IsCompleted);
            release.Set();
            using var result = await reading;
            Assert.Equal(new byte[] { 42 }, result.Buffer);
        }
        finally { release.Set(); }
    }

    [Theory]
    [InlineData("utf-16")]
    [InlineData("utf-16BE")]
    [InlineData("utf-8")]
    public async Task WindowsTextPreview_DecodesBom(string encodingName)
    {
        var encoding = Encoding.GetEncoding(encodingName);
        const string expected = "日本語のプレビュー\nabc";
        byte[] source = [.. encoding.GetPreamble(), .. encoding.GetBytes(expected)];
        using var vm = new FilePreviewViewModel(new MountedFilePreviewService("X:\\", _ => new MemoryStream(source)));
        vm.SelectedItem = new PreviewEntry("test.txt", "test.txt", false);
        await vm.OpenCommand.ExecuteAsync(null);
        Assert.Equal(expected, vm.Text);
    }

    [Fact]
    public void CancellingReader_RemovesRegistryEntryAndZerosBuffer_WithoutAnActivity()
    {
        var registry = new StreamingFileRegistry();
        using var lifetime = new CancellationTokenSource();
        using var content = new MemoryContent(lifetime.Token);
        string id = registry.Add(content);
        lifetime.Cancel();
        Assert.Throws<FileNotFoundException>(() => registry.Get(id));
        Assert.All(content.Bytes, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task SimultaneousLogoutAndReaderCancellation_DoesNotDeadlockOrRetainPlaintext()
    {
        for (int i = 0; i < 50; i++)
        {
            var registry = new StreamingFileRegistry();
            using var lifetime = new CancellationTokenSource();
            using var content = new MemoryContent(lifetime.Token);
            string id = registry.Add(content);
            await Task.WhenAll(Task.Run(lifetime.Cancel), Task.Run(registry.Clear)).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Throws<FileNotFoundException>(() => registry.Get(id));
            Assert.All(content.Bytes, b => Assert.Equal(0, b));
        }
    }

    private sealed class Listings(Func<string, CancellationToken, Task<PreviewEntry[]>> list) : IMountedFilePreviewService
    {
        public Task<PreviewEntry[]> ListAsync(string relative, CancellationToken ct) => list(relative, ct);
        public Task<SecureBuffer> ReadAsync(string relative, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class MemoryContent(CancellationToken ct) : ReadOnlyFileContent("clip.mp4", 3, ct)
    {
        public byte[] Bytes { get; } = [1, 2, 3];
        protected override ValueTask<int> ReadCoreAsync(long offset, Memory<byte> destination, CancellationToken cancellation)
        { Bytes.AsMemory((int)offset, destination.Length).CopyTo(destination); return ValueTask.FromResult(destination.Length); }
        protected override void ClearBuffers() => System.Security.Cryptography.CryptographicOperations.ZeroMemory(Bytes);
    }
}
