namespace CistaNAS.Wasm.Helpers;

/// <summary>
/// ファイル拡張子からメディア種別・MIMEタイプを判定。
/// </summary>
public static class MediaHelper
{
    public enum MediaType { None, Image, Video, Audio }

    private static readonly Dictionary<string, string> MimeMap = new(StringComparer.OrdinalIgnoreCase)
    {
        // Image
        [".jpg"] = "image/jpeg", [".jpeg"] = "image/jpeg", [".png"] = "image/png",
        [".gif"] = "image/gif", [".webp"] = "image/webp", [".bmp"] = "image/bmp",
        [".svg"] = "image/svg+xml", [".ico"] = "image/x-icon", [".tiff"] = "image/tiff",
        [".tif"] = "image/tiff", [".avif"] = "image/avif",
        // Video
        [".mp4"] = "video/mp4", [".webm"] = "video/webm", [".ogv"] = "video/ogg",
        [".mov"] = "video/quicktime", [".avi"] = "video/x-msvideo", [".mkv"] = "video/x-matroska",
        [".m4v"] = "video/mp4", [".3gp"] = "video/3gpp",
        // Audio
        [".mp3"] = "audio/mpeg", [".wav"] = "audio/wav", [".ogg"] = "audio/ogg",
        [".oga"] = "audio/ogg", [".aac"] = "audio/aac", [".flac"] = "audio/flac",
        [".m4a"] = "audio/mp4", [".wma"] = "audio/x-ms-wma", [".opus"] = "audio/opus",
    };

    public static MediaType GetMediaType(string fileName)
    {
        string ext = Path.GetExtension(fileName);
        if (!MimeMap.TryGetValue(ext, out var mime)) return MediaType.None;
        if (mime.StartsWith("image/", StringComparison.Ordinal)) return MediaType.Image;
        if (mime.StartsWith("video/", StringComparison.Ordinal)) return MediaType.Video;
        if (mime.StartsWith("audio/", StringComparison.Ordinal)) return MediaType.Audio;
        return MediaType.None;
    }

    public static string? GetMimeType(string fileName)
    {
        string ext = Path.GetExtension(fileName);
        return MimeMap.TryGetValue(ext, out var mime) ? mime : null;
    }

    public static bool IsMedia(string fileName) => GetMediaType(fileName) != MediaType.None;
}
