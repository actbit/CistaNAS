using CistaNAS.Web.Helpers;

namespace CistaNAS.Tests;

public class MediaHelperTests
{
    // ---- MIME タイプ ----

    [Theory]
    [InlineData("photo.jpg", "image/jpeg")]
    [InlineData("photo.jpeg", "image/jpeg")]
    [InlineData("icon.png", "image/png")]
    [InlineData("anim.gif", "image/gif")]
    [InlineData("img.webp", "image/webp")]
    [InlineData("pic.avif", "image/avif")]
    [InlineData("movie.mp4", "video/mp4")]
    [InlineData("clip.webm", "video/webm")]
    [InlineData("song.mp3", "audio/mpeg")]
    [InlineData("track.flac", "audio/flac")]
    [InlineData("audio.ogg", "audio/ogg")]
    [InlineData("audio.opus", "audio/opus")]
    public void GetMimeType_KnownExtensions_ReturnsCorrectMime(string fileName, string expected)
    {
        Assert.Equal(expected, MediaHelper.GetMimeType(fileName));
    }

    [Theory]
    [InlineData("data.xyz")]
    [InlineData("noext")]
    [InlineData(".")]
    public void GetMimeType_UnknownOrNoExtension_ReturnsNull(string fileName)
    {
        Assert.Null(MediaHelper.GetMimeType(fileName));
    }

    [Fact]
    public void GetMimeType_CaseInsensitive()
    {
        Assert.Equal("image/jpeg", MediaHelper.GetMimeType("PHOTO.JPG"));
        Assert.Equal("video/mp4", MediaHelper.GetMimeType("Movie.Mp4"));
    }

    // ---- メディア種別 ----

    [Theory]
    [InlineData("photo.jpg", MediaHelper.MediaType.Image)]
    [InlineData("img.webp", MediaHelper.MediaType.Image)]
    [InlineData("movie.mp4", MediaHelper.MediaType.Video)]
    [InlineData("clip.mkv", MediaHelper.MediaType.Video)]
    [InlineData("song.mp3", MediaHelper.MediaType.Audio)]
    [InlineData("track.flac", MediaHelper.MediaType.Audio)]
    public void GetMediaType_MediaFiles_ReturnsCorrectType(string fileName, MediaHelper.MediaType expected)
    {
        Assert.Equal(expected, MediaHelper.GetMediaType(fileName));
    }

    [Theory]
    [InlineData("doc.pdf")]
    [InlineData("archive.zip")]
    [InlineData("data.bin")]
    public void GetMediaType_NonMediaFiles_ReturnsNone(string fileName)
    {
        Assert.Equal(MediaHelper.MediaType.None, MediaHelper.GetMediaType(fileName));
    }

    // ---- IsMedia ----

    [Theory]
    [InlineData("song.ogg", true)]
    [InlineData("doc.pdf", false)]
    [InlineData("archive.zip", false)]
    public void IsMedia_ReturnsCorrectBool(string fileName, bool expected)
    {
        Assert.Equal(expected, MediaHelper.IsMedia(fileName));
    }
}
