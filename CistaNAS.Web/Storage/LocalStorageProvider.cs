using System.Runtime.InteropServices;

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
        FileStream? lockStream = null;
        try
        {
            lockStream = new FileStream(fullPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                lockStream.Lock(0, 1);
        }
        catch
        {
            lockStream?.Dispose();
            throw;
        }
        return Task.FromResult<IDisposable>(new FileLockReleaser(lockStream));
    }

    /// <summary>ローカルファイルベースのロックは削除不要（インターフェース実装のみ）。</summary>
    public void RemoveLock(string lockPath)
    {
        // ファイルベースロックは IDisposable で自動解放されるため、ここでは何もしない
    }

    /// <summary>
    /// blobPath を <see cref="_basePath"/> 配下に解決する。
    /// パストラバーサルを防ぐため、絶対パス・".." セグメント・ベース外パスを拒否する。
    /// </summary>
    private string ToFullPath(string blobPath)
    {
        ArgumentException.ThrowIfNullOrEmpty(blobPath);

        // 1. 絶対パスを拒否（Path.Combine の第二引数絶対パス上書き攻撃を防ぐ）
        if (Path.IsPathRooted(blobPath))
            throw new UnauthorizedAccessException("絶対パスは使用できません。");

        // 2. セグメント単位のチェック: ".." および "." を拒否。
        // 部分文字列一致（例: "version..1.0"）ではなく、パス区切りで分割して検査することで
        // 正当なボリューム名（.. を含む）でも動作するようにする。
        string normalizedSeparators = blobPath.Replace('/', Path.DirectorySeparatorChar)
                                             .Replace('\\', Path.DirectorySeparatorChar);
        foreach (var segment in normalizedSeparators.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment == "..")
                throw new UnauthorizedAccessException("相対親参照 (..) は使用できません。");
            if (segment == ".")
                throw new UnauthorizedAccessException("相対カレント参照 (.) は使用できません。");
        }

        // 3. 正規化してベース配下であることを確認
        var normalized = Path.GetFullPath(
            Path.Combine(_basePath, blobPath.Replace('/', Path.DirectorySeparatorChar)));
        var baseFull = Path.GetFullPath(_basePath)
            .TrimEnd(Path.DirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        var normalizedNoSep = normalized.TrimEnd(Path.DirectorySeparatorChar);
        var baseFullNoSep = Path.GetFullPath(_basePath).TrimEnd(Path.DirectorySeparatorChar);

        if (!normalized.StartsWith(baseFull, StringComparison.Ordinal)
            && !string.Equals(normalizedNoSep, baseFullNoSep, StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("パスがベースディレクトリ外です。");
        }
        return normalized;
    }

    private static void ListRecursive(string dir, string basePath, List<string> results)
    {
        foreach (var file in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
            results.Add(Path.GetRelativePath(basePath, file).Replace('\\', '/'));
    }

    private sealed class FileLockReleaser(FileStream fs) : IDisposable
    {
        public void Dispose()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                try { fs.Unlock(0, 1); } catch (IOException) { }
            fs.Dispose();
        }
    }
}
