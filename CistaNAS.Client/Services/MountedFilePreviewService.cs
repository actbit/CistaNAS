using CistaNAS.Client.Security;

namespace CistaNAS.Client.Services;

public interface IMountedFilePreviewService
{
    Task<PreviewEntry[]> ListAsync(string relative, CancellationToken ct);
    Task<SecureBuffer> ReadAsync(string relative, CancellationToken ct);
}

/// <summary>Mounted Dokan content is read into owned RAM buffers, without local copies.</summary>
public sealed class MountedFilePreviewService : IMountedFilePreviewService
{
    public const int ImageLimit = 32 * 1024 * 1024;
    public const int TextLimit = 2 * 1024 * 1024;
    private readonly string _root;
    private readonly Func<string, Stream> _open;
    public MountedFilePreviewService(string mountPoint, Func<string, Stream>? open = null)
    {
        if (mountPoint.Length is < 2 or > 3 || !char.IsAsciiLetter(mountPoint[0]) || mountPoint[1] != ':' ||
            (mountPoint.Length == 3 && mountPoint[2] != '\\'))
            throw new ArgumentException("A mounted drive letter is required.", nameof(mountPoint));
        _root = Path.GetFullPath(mountPoint.TrimEnd('\\') + "\\");
        _open = open ?? (path => new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            4096, FileOptions.Asynchronous));
    }

    public string Root => _root;
    public string Resolve(string relative)
    {
        if (Path.IsPathRooted(relative) || relative.Contains(':') ||
            relative.Split('/', '\\').Contains("..")) throw new ArgumentException("Invalid preview path.");
        string path = Path.GetFullPath(Path.Combine(_root, relative));
        if (!path.StartsWith(_root, StringComparison.OrdinalIgnoreCase) &&
            !path.Equals(_root.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Path is outside the mounted volume.");
        return path;
    }

    public static bool IsImage(string name) => Path.GetExtension(name).ToLowerInvariant() is
        ".png" or ".jpg" or ".jpeg" or ".gif" or ".bmp" or ".webp";
    public static bool IsText(string name) => Path.GetExtension(name).ToLowerInvariant() is
        ".txt" or ".md" or ".json" or ".csv" or ".log" or ".xml" or ".yaml" or ".yml" or ".cs";

    public Task<PreviewEntry[]> ListAsync(string relative, CancellationToken ct) => Task.Run(() =>
    {
        var entries = new List<PreviewEntry>();
        foreach (string path in Directory.EnumerateFileSystemEntries(Resolve(relative)))
        {
            ct.ThrowIfCancellationRequested();
            entries.Add(new(Path.GetFileName(path), Path.GetRelativePath(_root, path), Directory.Exists(path)));
        }
        return entries.OrderByDescending(item => item.IsFolder)
            .ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }, ct);

    public Task<SecureBuffer> ReadAsync(string relative, CancellationToken ct) => Task.Run(async () =>
    {
        int limit = IsImage(relative) ? ImageLimit : IsText(relative) ? TextLimit
            : throw new NotSupportedException("組み込みViewerは画像・テキストに対応しています。");
        ct.ThrowIfCancellationRequested();
        using Stream source = _open(Resolve(relative));
        if (source.Length > limit) throw new IOException($"表示できるサイズの上限は {limit / 1024 / 1024} MiB です。");
        var buffer = new SecureBuffer(new byte[checked((int)source.Length)]);
        try
        {
            await source.ReadExactlyAsync(buffer.Buffer, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            return buffer;
        }
        catch { buffer.Dispose(); throw; }
    }, ct);
}

public sealed record PreviewEntry(string Name, string RelativePath, bool IsFolder)
{
    public string Label => IsFolder ? $"📁 {Name}" : Name;
}
