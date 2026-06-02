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
}
