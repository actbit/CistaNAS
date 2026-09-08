using CistaNAS.Client.Api;

namespace CistaNAS.Mobile.Core.Services;

/// <summary>ブラウザ表示用のノード。フォルダは合成ノード (サーバーには存在しない)。</summary>
public sealed class FileNode
{
    public required string Name { get; init; }
    /// <summary>ルートからの相対パス ('/' 区切り、先頭スラなし)。フォルダは末尾スラなし。</summary>
    public required string FullPath { get; init; }
    public required bool IsFolder { get; init; }
    public long Length { get; init; }
    public DateTimeOffset ModifiedAt { get; init; }
    public List<FileNode> Children { get; init; } = [];

    public FileCategory Category => IsFolder ? FileCategory.Other : FileCategoryService.Categorize(Name);
}

/// <summary>
/// サーバー暗号化ボリュームのフラットなファイル一覧 (Name に '/' 区切りパスを含みうる) から
/// フォルダツリーを構築する純粋関数群。
/// </summary>
public static class FileTreeBuilder
{
    /// <summary>指定パス直下の子ノードを返す (フォルダ優先、次に名前順)。</summary>
    /// <param name="files">全ファイルのフラット一覧。</param>
    /// <param name="currentPath">現在のフォルダパス ('/' 区切り)。ルートは ""。</param>
    public static List<FileNode> GetChildren(IEnumerable<FileMetadata> files, string currentPath)
    {
        string prefix = string.IsNullOrEmpty(currentPath) ? "" : currentPath.Trim('/') + "/";
        var folders = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var fileNodes = new List<FileNode>();

        foreach (var f in files)
        {
            string name = NormalizePath(f.Name);
            if (name.Length == 0 || !name.StartsWith(prefix, StringComparison.Ordinal))
                continue;
            string rest = name[prefix.Length..];
            if (rest.Length == 0) continue;

            int slash = rest.IndexOf('/');
            if (slash >= 0)
            {
                // パス途中のセグメントは合成フォルダ
                folders.Add(rest[..slash]);
            }
            else
            {
                fileNodes.Add(new FileNode
                {
                    Name = rest,
                    FullPath = prefix + rest,
                    IsFolder = false,
                    Length = f.Length,
                    ModifiedAt = f.ModifiedAt,
                });
            }
        }

        var result = new List<FileNode>(folders.Count + fileNodes.Count);
        foreach (string folder in folders)
        {
            result.Add(new FileNode
            {
                Name = folder,
                FullPath = prefix + folder,
                IsFolder = true,
            });
        }
        fileNodes.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        result.AddRange(fileNodes);
        return result;
    }

    /// <summary>パンくずリスト用: パスのセグメント列 (ルートは空リスト)。</summary>
    public static IReadOnlyList<string> GetBreadcrumbs(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return [];
        return path.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>1 つ上のフォルダへ。ルートなら null。</summary>
    public static string? GetParentPath(string path)
    {
        string trimmed = (path ?? "").Trim('/');
        if (trimmed.Length == 0) return null;
        int slash = trimmed.LastIndexOf('/');
        return slash < 0 ? "" : trimmed[..slash];
    }

    /// <summary>連続スラッシュの正規化と前后の '/' 除去。ディレクトリトラバーサル要素は送信前に排除済み前提。</summary>
    private static string NormalizePath(string name)
    {
        var parts = name.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return string.Join('/', parts.Where(p => p is not "." and not ".."));
    }
}
