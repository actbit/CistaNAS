using Android.Content;
using CistaNAS.Mobile.Core.Abstractions;

namespace CistaNAS.Mobile.Platform;

/// <summary>外部アプリ委譲用の一時ファイルキャッシュ (CacheDir/externalviewer)。</summary>
public sealed class AndroidFileCacheProvider : IFileCacheProvider
{
    private static readonly string CacheDir =
        Path.Combine(Application.Context.CacheDir!.Path!, "externalviewer");

    public Stream OpenWrite(string fileName)
    {
        Directory.CreateDirectory(CacheDir);
        return File.Create(GetPath(fileName));
    }

    public string GetPath(string fileName) => Path.Combine(CacheDir, fileName);

    public void Clear()
    {
        if (!Directory.Exists(CacheDir)) return;
        foreach (string file in Directory.EnumerateFiles(CacheDir))
        {
            try { File.Delete(file); } catch (IOException) { /* 使用中は無視 */ }
        }
    }
}
