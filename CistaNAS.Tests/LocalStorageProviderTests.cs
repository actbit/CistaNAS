using CistaNAS.Web.Storage;

namespace CistaNAS.Tests;

/// <summary>
/// LocalStorageProvider のセキュリティ境界（パストラバーサル）のテスト。
/// 修正 (C-2): ToFullPath が絶対パス・".." を含むパス・ベース外パスを拒否することを確認。
/// </summary>
public class LocalStorageProviderTests : IDisposable
{
    private readonly string _dataRoot;
    private readonly LocalStorageProvider _provider;

    public LocalStorageProviderTests()
    {
        _dataRoot = Path.Combine(Path.GetTempPath(), "cista-lsp-test-" + Guid.NewGuid().ToString("N"));
        _provider = new LocalStorageProvider(_dataRoot);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dataRoot, recursive: true); } catch { }
    }

    [Fact]
    public async Task WriteAsync_NormalPath_Succeeds()
    {
        // 正常パスは通る
        var stream = new MemoryStream(new byte[] { 1, 2, 3 });
        await _provider.WriteAsync("vol/file.bin", stream);
        Assert.True(await _provider.ExistsAsync("vol/file.bin"));
    }

    [Fact]
    public async Task WriteAsync_AbsolutePath_Throws()
    {
        // Windows 絶対パスは拒否される
        var stream = new MemoryStream(new byte[] { 1, 2, 3 });
        var ex = await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => _provider.WriteAsync(@"C:\Windows\System32\drivers\etc\hosts", stream));
        Assert.Contains("絶対パス", ex.Message);
    }

    [Fact]
    public async Task WriteAsync_DotDotTraversal_Throws()
    {
        // 親ディレクトリ参照は拒否される
        var stream = new MemoryStream(new byte[] { 1, 2, 3 });
        var ex = await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => _provider.WriteAsync("../escaped.bin", stream));
        Assert.Contains("相対親参照", ex.Message);
    }

    [Fact]
    public async Task WriteAsync_DeepDotDotTraversal_Throws()
    {
        // 多段の ".." も拒否
        var stream = new MemoryStream(new byte[] { 1, 2, 3 });
        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => _provider.WriteAsync("vol/../../escaped.bin", stream));
    }

    [Fact]
    public async Task WriteAsync_NestedPath_CreatesDirectories()
    {
        // 通常のネストは OK で、ディレクトリ自動作成
        var stream = new MemoryStream(new byte[] { 1, 2, 3 });
        await _provider.WriteAsync("a/b/c/d.bin", stream);
        Assert.True(await _provider.ExistsAsync("a/b/c/d.bin"));
    }

    [Fact]
    public async Task WriteAsync_EmptyPath_Throws()
    {
        // 空パスは拒否
        var stream = new MemoryStream(new byte[] { 1, 2, 3 });
        await Assert.ThrowsAsync<ArgumentException>(
            () => _provider.WriteAsync("", stream));
    }

    [Fact]
    public async Task WriteAtomicAsync_CopyFailure_PreservesOriginalAndRemovesTemporaryFile()
    {
        byte[] original = [1, 2, 3];
        await _provider.WriteAtomicAsync("vol/catalog.json", new MemoryStream(original));
        using var broken = new FailingCopyStream();
        await Assert.ThrowsAsync<IOException>(() => _provider.WriteAtomicAsync("vol/catalog.json", broken));
        Assert.Equal(original, await _provider.ReadAsync("vol/catalog.json"));
        Assert.Equal(new[] { "vol/catalog.json" }, await _provider.ListAsync("vol"));
    }

    [Fact]
    public async Task WriteAtomicAsync_CancellationBeforePublish_PreservesOriginalAndRemovesTemporaryFile()
    {
        byte[] original = [1, 2, 3];
        await _provider.WriteAtomicAsync("vol/catalog.json", new MemoryStream(original));
        using var cancellation = new CancellationTokenSource();
        using var content = new CancelAfterCopyStream(cancellation);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _provider.WriteAtomicAsync("vol/catalog.json", content, cancellation.Token));
        Assert.Equal(original, await _provider.ReadAsync("vol/catalog.json"));
        Assert.Equal(new[] { "vol/catalog.json" }, await _provider.ListAsync("vol"));
    }

    [Fact]
    public async Task AtomicReplacement_ConcurrentReadersAlwaysSeeACompleteVersion()
    {
        byte[] first = Enumerable.Repeat((byte)11, 512 * 1024).ToArray();
        byte[] second = Enumerable.Repeat((byte)22, first.Length).ToArray();
        await _provider.WriteAtomicAsync("vol/catalog.json", new MemoryStream(first));
        Task writer = Task.Run(async () =>
        {
            for (int i = 0; i < 60; i++)
                await _provider.WriteAtomicAsync("vol/catalog.json", new MemoryStream(i % 2 == 0 ? second : first));
        });
        Task[] readers = Enumerable.Range(0, 4).Select(_ => Task.Run(async () =>
        {
            for (int i = 0; i < 100; i++)
            {
                byte[] data = (await _provider.ReadAsync("vol/catalog.json"))!;
                Assert.Equal(first.Length, data.Length);
                Assert.True(data.AsSpan().SequenceEqual(first) || data.AsSpan().SequenceEqual(second));
            }
        })).ToArray();
        await Task.WhenAll(readers.Append(writer)).WaitAsync(TimeSpan.FromSeconds(30));
    }

    private sealed class FailingCopyStream : MemoryStream
    {
        public override async Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        {
            await destination.WriteAsync(new byte[] { 99 }, cancellationToken);
            throw new IOException("Simulated interrupted metadata save");
        }
    }

    private sealed class CancelAfterCopyStream(CancellationTokenSource cancellation) : MemoryStream
    {
        public override async Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        {
            await destination.WriteAsync(new byte[] { 99 }, cancellationToken);
            cancellation.Cancel();
        }
    }
}
