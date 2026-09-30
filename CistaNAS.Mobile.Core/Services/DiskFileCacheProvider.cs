using CistaNAS.Mobile.Core.Abstractions;

namespace CistaNAS.Mobile.Core.Services;

/// <summary>外部表示用キャッシュ。ファイル名を検証し、セッション終了時に削除可能にする。</summary>
public sealed class DiskFileCacheProvider(string directory) : IFileCacheProvider
{
    public Stream OpenWrite(string fileName)
    {
        string path = GetPath(fileName);
        Directory.CreateDirectory(directory);
        return new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read | FileShare.Delete);
    }

    public string GetPath(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName) || fileName is "." or ".."
            || fileName.IndexOfAny(['/', '\\', ':']) >= 0
            || fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new ArgumentException("キャッシュには単一のファイル名が必要です。", nameof(fileName));
        return Path.Combine(directory, fileName);
    }

    public void Delete(string fileName) => File.Delete(GetPath(fileName));

    public void Clear()
    {
        if (!Directory.Exists(directory)) return;
        foreach (string file in Directory.EnumerateFiles(directory)) File.Delete(file);
    }
}
