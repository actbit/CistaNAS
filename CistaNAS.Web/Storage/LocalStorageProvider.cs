namespace CistaNAS.Web.Storage;

/// <summary>ローカルファイルシステムを使用する IStorageProvider 実装（デフォルト）。</summary>
public sealed class LocalStorageProvider : IStorageProvider
{
    private readonly string _basePath;

    public LocalStorageProvider(string basePath)
    {
        _basePath = basePath;
        Directory.CreateDirectory(_basePath);
    }

    public async Task<byte[]?> ReadAsync(string blobPath, CancellationToken ct = default)
    {
        string fullPath = ToFullPath(blobPath);
        if (!File.Exists(fullPath)) return null;
        return await File.ReadAllBytesAsync(fullPath, ct);
    }

    public async Task WriteAsync(string blobPath, Stream content, CancellationToken ct = default)
    {
        string fullPath = ToFullPath(blobPath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        using var fs = File.Create(fullPath);
        await content.CopyToAsync(fs, ct);
    }

    public async Task WriteAtomicAsync(string blobPath, Stream content, CancellationToken ct = default)
    {
        string fullPath = ToFullPath(blobPath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        string tmpPath = fullPath + ".tmp";
        using (var fs = File.Create(tmpPath))
            await content.CopyToAsync(fs, ct);
        File.Move(tmpPath, fullPath, overwrite: true);
    }

    public Task DeleteAsync(string blobPath, CancellationToken ct = default)
    {
        string fullPath = ToFullPath(blobPath);
        if (File.Exists(fullPath)) File.Delete(fullPath);
        return Task.CompletedTask;
    }

    public Task<bool> ExistsAsync(string blobPath, CancellationToken ct = default)
    {
        return Task.FromResult(File.Exists(ToFullPath(blobPath)));
    }

    public Task<IReadOnlyList<string>> ListAsync(string? prefix, CancellationToken ct = default)
    {
        var results = new List<string>();
        if (!Directory.Exists(_basePath)) return Task.FromResult<IReadOnlyList<string>>(results);

        if (string.IsNullOrEmpty(prefix))
        {
            foreach (var file in Directory.GetFiles(_basePath))
                results.Add(Path.GetFileName(file));
            foreach (var dir in Directory.GetDirectories(_basePath))
                ListRecursive(dir, _basePath, results);
        }
        else
        {
            string prefixDir = Path.Combine(_basePath, prefix.Replace('/', Path.DirectorySeparatorChar));
            if (Directory.Exists(prefixDir))
                ListRecursive(prefixDir, _basePath, results);
        }

        return Task.FromResult<IReadOnlyList<string>>(results);
    }

    public Task<IDisposable> AcquireLockAsync(string lockPath, CancellationToken ct = default)
    {
        string fullPath = ToFullPath(lockPath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        var lockStream = new FileStream(fullPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        lockStream.Lock(0, 1);
        return Task.FromResult<IDisposable>(new FileLockReleaser(lockStream));
    }

    private string ToFullPath(string blobPath) => Path.Combine(_basePath, blobPath.Replace('/', Path.DirectorySeparatorChar));

    private static void ListRecursive(string dir, string basePath, List<string> results)
    {
        foreach (var file in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
            results.Add(Path.GetRelativePath(basePath, file).Replace('\\', '/'));
    }

    private sealed class FileLockReleaser(FileStream fs) : IDisposable
    {
        public void Dispose()
        {
            try { fs.Unlock(0, 1); } catch { }
            fs.Dispose();
        }
    }
}
