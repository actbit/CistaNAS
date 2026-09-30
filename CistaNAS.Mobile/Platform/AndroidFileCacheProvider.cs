using Android.Content;
using CistaNAS.Mobile.Core.Abstractions;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Platform;

/// <summary>外部アプリ委譲用の一時ファイルキャッシュ (CacheDir/externalviewer)。</summary>
public sealed class AndroidFileCacheProvider : IFileCacheProvider
{
    private readonly DiskFileCacheProvider _cache = new(
        Path.Combine(Application.Context.CacheDir!.Path!, "externalviewer"));

    public Stream OpenWrite(string fileName)
    {
        return _cache.OpenWrite(fileName);
    }

    public string GetPath(string fileName) => _cache.GetPath(fileName);

    public void Delete(string fileName) => _cache.Delete(fileName);

    public void Clear()
    {
        _cache.Clear();
    }
}
