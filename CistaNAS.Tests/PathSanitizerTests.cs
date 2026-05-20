using CistaNAS.Web.Api;
using CistaNAS.Web.Models;

namespace CistaNAS.Tests;

public class PathSanitizerTests
{
    [Fact]
    public void NormalPath_ReturnsSame()
    {
        Assert.Equal("docs/readme.txt", PathSanitizer.SanitizeFileName("docs/readme.txt"));
    }

    [Fact]
    public void PathTraversal_StripsDots()
    {
        Assert.Equal("etc/passwd", PathSanitizer.SanitizeFileName("../../etc/passwd"));
    }

    [Fact]
    public void MixedTraversal_StripsAllDots()
    {
        Assert.Equal("a/b/c.txt", PathSanitizer.SanitizeFileName("a/../b/../c.txt"));
    }

    [Fact]
    public void SingleDot_Strips()
    {
        Assert.Equal("secret.txt", PathSanitizer.SanitizeFileName("./secret.txt"));
    }

    [Fact]
    public void LeadingSlash_Strips()
    {
        Assert.Equal("absolute/path.txt", PathSanitizer.SanitizeFileName("/absolute/path.txt"));
    }

    [Fact]
    public void Backslash_Converts()
    {
        Assert.Equal("dir/file.txt", PathSanitizer.SanitizeFileName("dir\\file.txt"));
    }

    [Fact]
    public void UrlEncodedTraversal_Strips()
    {
        Assert.Equal("secret", PathSanitizer.SanitizeFileName("%2e%2e/secret"));
    }

    [Fact]
    public void EmptyAfterSanitization_Throws()
    {
        Assert.Throws<FileServiceException>(() => PathSanitizer.SanitizeFileName("../.."));
    }

    [Fact]
    public void OnlyDots_Throws()
    {
        Assert.Throws<FileServiceException>(() => PathSanitizer.SanitizeFileName("."));
    }

    [Fact]
    public void NormalFilename_NoSubpath_ReturnsSame()
    {
        Assert.Equal("photo.jpg", PathSanitizer.SanitizeFileName("photo.jpg"));
    }

    [Fact]
    public void InvalidFileNameChars_Throws()
    {
        Assert.Throws<FileServiceException>(() => PathSanitizer.SanitizeFileName("bad|name.txt"));
    }

    [Fact]
    public void DoubleEncodedTraversal_NotFullyDecoded()
    {
        // Uri.UnescapeDataString は1段階しかデコードしない: %252e → %2e (not ..)
        // よって %2e%2e は ".." ではなくそのまま残る — 安全
        string result = PathSanitizer.SanitizeFileName("%252e%252e/secret");
        Assert.DoesNotContain("..", result);
    }

    [Fact]
    public void NullInput_Throws()
    {
        Assert.Throws<NullReferenceException>(() => PathSanitizer.SanitizeFileName(null!));
    }

    [Fact]
    public void MultipleSlashes_Collapses()
    {
        Assert.Equal("a/b/c", PathSanitizer.SanitizeFileName("a///b///c"));
    }

    [Fact]
    public void DeepTraversal_StripsDotsOnly()
    {
        // .. だけが取り除かれ、残りのセグメントは保持される
        string result = PathSanitizer.SanitizeFileName("a/b/../../c/../d/../../safe.txt");
        Assert.DoesNotContain("..", result);
        Assert.EndsWith("safe.txt", result);
    }
}
