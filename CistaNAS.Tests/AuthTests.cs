using CistaNAS.Web.Configuration;
using CistaNAS.Web.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public class AuthTests : IDisposable
{
    private readonly string _dataRoot = Path.Combine(Path.GetTempPath(), "cista-test-" + Guid.NewGuid().ToString("N"));

    private (AuthService auth, CistaNasOptions opt) Build(string adminPassword = "admin-pw")
    {
        var opt = new CistaNasOptions
        {
            DataRoot = _dataRoot,
            Auth = new AuthOptions { DefaultAdminUser = "admin", DefaultAdminPassword = adminPassword, Pbkdf2Iterations = 10_000 },
        };
        var io = Options.Create(opt);
        var store = new UserStore(io, NullLogger<UserStore>.Instance);
        var key = new JwtSigningKey(System.Security.Cryptography.RandomNumberGenerator.GetBytes(48));
        return (new AuthService(store, key, io), opt);
    }

    [Fact]
    public void Authenticate_Succeeds_WithSeededAdmin()
    {
        var (auth, _) = Build();
        var res = auth.Authenticate("admin", "admin-pw");
        Assert.NotNull(res);
        Assert.Equal("Bearer", res!.TokenType);
        Assert.False(string.IsNullOrWhiteSpace(res.AccessToken));
        Assert.True(res.ExpiresAt > DateTimeOffset.UtcNow);
    }

    [Theory]
    [InlineData("admin", "wrong")]
    [InlineData("nobody", "admin-pw")]
    [InlineData("", "")]
    public void Authenticate_Fails_WithBadCredentials(string user, string pw)
    {
        var (auth, _) = Build();
        Assert.Null(auth.Authenticate(user, pw));
    }

    [Fact]
    public async Task IssuedToken_Validates_AndCarriesIdentity()
    {
        var (auth, _) = Build();
        var res = auth.Authenticate("admin", "admin-pw");
        Assert.NotNull(res);

        var principal = await auth.ValidateTokenAsync(res!.AccessToken);
        Assert.NotNull(principal);
        Assert.Equal("admin", principal!.Identity?.Name);
        Assert.True(principal.IsInRole("admin"));
    }

    [Fact]
    public async Task ValidateToken_Rejects_Tampered()
    {
        var (auth, _) = Build();
        var res = auth.Authenticate("admin", "admin-pw")!;
        string tampered = res.AccessToken[..^2] + (res.AccessToken[^1] == 'A' ? "BB" : "AA");
        Assert.Null(await auth.ValidateTokenAsync(tampered));
    }

    [Fact]
    public void Seeding_Persists_AcrossInstances()
    {
        Build();                       // 1 回目：シード
        var (auth2, _) = Build();      // 2 回目：users.json から読み込み
        Assert.NotNull(auth2.Authenticate("admin", "admin-pw"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true);
    }
}
