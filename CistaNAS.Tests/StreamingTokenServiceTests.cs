using CistaNAS.Web.Services;

namespace CistaNAS.Tests;

public class StreamingTokenServiceTests
{
    [Fact]
    public void Validate_ValidToken_ReturnsClaims()
    {
        var svc = new StreamingTokenService();
        string token = svc.Issue("alice", "vol1", "photo.jpg");

        var result = svc.Validate(token);

        Assert.NotNull(result);
        Assert.Equal("alice", result.Value.Username);
        Assert.Equal("vol1", result.Value.VolumeName);
        Assert.Equal("photo.jpg", result.Value.FileName);
    }

    [Fact]
    public void Validate_TokenIsSingleUse()
    {
        var svc = new StreamingTokenService();
        string token = svc.Issue("alice", "vol1", "file.txt");

        var first = svc.Validate(token);
        var second = svc.Validate(token);

        Assert.NotNull(first);
        Assert.Null(second);
    }

    [Fact]
    public void Validate_UnknownToken_ReturnsNull()
    {
        var svc = new StreamingTokenService();
        Assert.Null(svc.Validate("nonexistent"));
    }

    [Fact]
    public void Issue_DifferentCalls_ProduceDifferentTokens()
    {
        var svc = new StreamingTokenService();
        string t1 = svc.Issue("alice", "vol1", "a.txt");
        string t2 = svc.Issue("alice", "vol1", "a.txt");
        Assert.NotEqual(t1, t2);
    }

    [Fact]
    public void Issue_Returns64CharHex()
    {
        var svc = new StreamingTokenService();
        string token = svc.Issue("u", "v", "f");
        Assert.Matches("^[0-9a-f]{64}$", token);
    }
}
