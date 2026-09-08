namespace CistaNAS.Mobile.Core.Services;

/// <summary>ファイルの表示カテゴリ。</summary>
public enum FileCategory
{
    Image,
    Video,
    Audio,
    Text,
    Other,
}

/// <summary>拡張子からカテゴリ / MIME 型を判定する。</summary>
public static class FileCategoryService
{
    private static readonly HashSet<string> ImageExt = new(StringComparer.OrdinalIgnoreCase)
        { ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic", ".avif" };

    private static readonly HashSet<string> VideoExt = new(StringComparer.OrdinalIgnoreCase)
        { ".mp4", ".mov", ".webm", ".mkv", ".avi", ".m4v", ".3gp" };

    private static readonly HashSet<string> AudioExt = new(StringComparer.OrdinalIgnoreCase)
        { ".mp3", ".wav", ".ogg", ".m4a", ".flac", ".aac" };

    private static readonly HashSet<string> TextExt = new(StringComparer.OrdinalIgnoreCase)
        { ".txt", ".md", ".markdown", ".json", ".xml", ".csv", ".tsv", ".log", ".ini", ".yaml", ".yml", ".cs", ".js", ".ts", ".py", ".html", ".css" };

    public static FileCategory Categorize(string fileName)
    {
        string ext = Path.GetExtension(fileName);
        if (ImageExt.Contains(ext)) return FileCategory.Image;
        if (VideoExt.Contains(ext)) return FileCategory.Video;
        if (AudioExt.Contains(ext)) return FileCategory.Audio;
        if (TextExt.Contains(ext)) return FileCategory.Text;
        return FileCategory.Other;
    }

    public static string GetMimeType(string fileName) => Path.GetExtension(fileName).ToLowerInvariant() switch
    {
        ".jpg" or ".jpeg" => "image/jpeg",
        ".png" => "image/png",
        ".gif" => "image/gif",
        ".webp" => "image/webp",
        ".bmp" => "image/bmp",
        ".avif" => "image/avif",
        ".heic" => "image/heic",
        ".mp4" or ".m4v" => "video/mp4",
        ".webm" => "video/webm",
        ".mkv" => "video/x-matroska",
        ".avi" => "video/x-msvideo",
        ".3gp" => "video/3gpp",
        ".mov" => "video/quicktime",
        ".mp3" => "audio/mpeg",
        ".wav" => "audio/wav",
        ".ogg" => "audio/ogg",
        ".m4a" => "audio/mp4",
        ".flac" => "audio/flac",
        ".aac" => "audio/aac",
        ".pdf" => "application/pdf",
        ".zip" => "application/zip",
        ".txt" or ".log" or ".ini" or ".cs" or ".js" or ".ts" or ".py" => "text/plain",
        ".md" or ".markdown" => "text/markdown",
        ".json" => "application/json",
        ".xml" or ".html" or ".css" => "text/xml",
        ".csv" => "text/csv",
        ".tsv" => "text/tab-separated-values",
        ".yaml" or ".yml" => "text/yaml",
        _ => "application/octet-stream",
    };

    /// <summary>一覧表示用のアイコン (Unicode グリフ)。</summary>
    public static string GetIcon(FileCategory category) => category switch
    {
        FileCategory.Image => "\U0001F5BC",  // 🖼
        FileCategory.Video => "\U0001F3AC",  // 🎬
        FileCategory.Audio => "\U0001F3B5",  // 🎵
        FileCategory.Text => "\U0001F4C4",   // 📄
        _ => "\U0001F4E6",                    // 📦
    };

    /// <summary>フォルダ用アイコン。</summary>
    public const string FolderIcon = "\U0001F4C1"; // 📁

    /// <summary>バイト数の簡易整形。</summary>
    public static string FormatSize(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double v = bytes;
        int u = 0;
        while (v >= 1024 && u < units.Length - 1)
        {
            v /= 1024;
            u++;
        }
        return u == 0 ? $"{bytes} {units[0]}" : $"{v:0.##} {units[u]}";
    }
}
