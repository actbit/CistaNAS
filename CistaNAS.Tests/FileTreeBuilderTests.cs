using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;
using Xunit;

namespace CistaNAS.Tests;

public class FileTreeBuilderTests
{
    private static FileMetadata Meta(string name) => new()
    {
        Name = name,
        Length = 100,
        CreatedAt = DateTimeOffset.UnixEpoch,
        ModifiedAt = DateTimeOffset.UnixEpoch,
    };

    [Fact]
    public void ルート直下のファイルとフォルダが分類される()
    {
        var files = new[] { Meta("a.txt"), Meta("docs/readme.md"), Meta("docs/img/pic.png") };
        var children = FileTreeBuilder.GetChildren(files, "");

        Assert.Equal(2, children.Count);
        var folder = Assert.Single(children, c => c.IsFolder);
        Assert.Equal("docs", folder.Name);
        var file = Assert.Single(children, c => !c.IsFolder);
        Assert.Equal("a.txt", file.FullPath);
    }

    [Fact]
    public void フォルダ配下の子が取得できる()
    {
        var files = new[] { Meta("docs/readme.md"), Meta("docs/img/pic.png"), Meta("docs/img/photo.jpg") };
        var children = FileTreeBuilder.GetChildren(files, "docs");

        Assert.Equal(2, children.Count);
        Assert.True(children[0].IsFolder);
        Assert.Equal("docs/img", children[0].FullPath);
        Assert.Equal("docs/readme.md", children[1].FullPath);
    }

    [Fact]
    public void フォルダが先_その後名前順でソートされる()
    {
        var files = new[] { Meta("b.txt"), Meta("a_folder/x.txt"), Meta("a.txt") };
        var children = FileTreeBuilder.GetChildren(files, "");

        Assert.Equal("a_folder", children[0].Name);
        Assert.Equal("a.txt", children[1].Name);
        Assert.Equal("b.txt", children[2].Name);
    }

    [Fact]
    public void 連続スラッシュや正規化が必要なパスも扱える()
    {
        var files = new[] { Meta("docs//x.txt"), Meta("docs/./y.txt") };
        var children = FileTreeBuilder.GetChildren(files, "docs");

        Assert.Equal(2, children.Count);
        Assert.Equal("docs/x.txt", children[0].FullPath);
        Assert.Equal("docs/y.txt", children[1].FullPath);
    }

    [Fact]
    public void パスプレフィックスが部分一致しないファイルは含まれない()
    {
        var files = new[] { Meta("docs2/x.txt") };
        Assert.Empty(FileTreeBuilder.GetChildren(files, "docs"));
    }

    [Fact]
    public void 親パスの取得()
    {
        Assert.Null(FileTreeBuilder.GetParentPath(""));
        Assert.Null(FileTreeBuilder.GetParentPath("/"));
        Assert.Equal("", FileTreeBuilder.GetParentPath("docs"));
        Assert.Equal("docs", FileTreeBuilder.GetParentPath("docs/img"));
    }

    [Fact]
    public void パンくずリスト()
    {
        Assert.Empty(FileTreeBuilder.GetBreadcrumbs(""));
        Assert.Equal(new[] { "docs", "img" }, FileTreeBuilder.GetBreadcrumbs("docs/img"));
    }
}
