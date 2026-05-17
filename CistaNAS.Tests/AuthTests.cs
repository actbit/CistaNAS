using CistaNAS.Web.Configuration;
using CistaNAS.Web.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public class AuthTests : IDisposable
{
    private readonly string _dataRoot = Path.Combine(Path.GetTempPath(), "cista-auth-" + Guid.NewGuid().ToString("N"));

    private (AuthService auth, UserStore store, CistaNasOptions opt, VolumeService vs) BuildWithVolume()
    {
        var opt = new CistaNasOptions
        {
            DataRoot = _dataRoot,
            Auth = new AuthOptions { Pbkdf2Iterations = 10_000 },
            Volume = new VolumeOptions { SectorSize = 512, KdfIterations = 10_000 },
        };
        var io = Options.Create(opt);
        var vs = new VolumeService(io);
        var store = new UserStore(io, NullLogger<UserStore>.Instance, new FakeServiceProvider(vs));
        var key = new JwtSigningKey(System.Security.Cryptography.RandomNumberGenerator.GetBytes(48));
        return (new AuthService(store, key, io), store, opt, vs);
    }

    private (AuthService auth, UserStore store, CistaNasOptions opt) Build()
    {
        var (auth, store, opt, _) = BuildWithVolume();
        return (auth, store, opt);
    }

    [Fact]
    public void CreateInitialAdmin_ThenAuthenticate()
    {
        var (auth, store, _) = Build();

        Assert.False(store.HasAnyUsers);
        store.CreateInitialAdmin("admin", "test-pw");
        Assert.True(store.HasAnyUsers);

        var res = auth.Authenticate("admin", "test-pw");
        Assert.NotNull(res);
        Assert.Equal("Bearer", res!.TokenType);
    }

    [Fact]
    public void CreateInitialAdmin_Fails_WhenUsersExist()
    {
        var (_, store, _) = Build();
        store.CreateInitialAdmin("admin", "pw");
        Assert.Throws<InvalidOperationException>(() => store.CreateInitialAdmin("admin2", "pw2"));
    }

    [Theory]
    [InlineData("admin", "wrong")]
    [InlineData("nobody", "test-pw")]
    [InlineData("", "")]
    public void Authenticate_Fails_WithBadCredentials(string user, string pw)
    {
        var (auth, store, _) = Build();
        store.CreateInitialAdmin("admin", "test-pw");
        Assert.Null(auth.Authenticate(user, pw));
    }

    [Fact]
    public async Task IssuedToken_Validates_AndCarriesIdentity()
    {
        var (auth, store, _) = Build();
        store.CreateInitialAdmin("admin", "pw");
        var res = auth.Authenticate("admin", "pw")!;

        var principal = await auth.ValidateTokenAsync(res.AccessToken);
        Assert.NotNull(principal);
        Assert.Equal("admin", principal!.Identity?.Name);
    }

    [Fact]
    public async Task ValidateToken_Rejects_Tampered()
    {
        var (auth, store, _) = Build();
        store.CreateInitialAdmin("admin", "pw");
        var res = auth.Authenticate("admin", "pw")!;
        string tampered = res.AccessToken[..^2] + (res.AccessToken[^1] == 'A' ? "BB" : "AA");
        Assert.Null(await auth.ValidateTokenAsync(tampered));
    }

    [Fact]
    public void ChangePassword_Reauth_WithNewPassword()
    {
        var (auth, store, _, _) = BuildWithVolume();
        store.CreateInitialAdmin("admin", "old-pw");

        bool ok = auth.ChangePassword("admin", "old-pw", "new-pw");
        Assert.True(ok);

        Assert.Null(auth.Authenticate("admin", "old-pw"));
        Assert.NotNull(auth.Authenticate("admin", "new-pw"));
    }

    [Fact]
    public void ChangePassword_WrongOld_Fails()
    {
        var (auth, store, _, _) = BuildWithVolume();
        store.CreateInitialAdmin("admin", "pw");

        bool ok = auth.ChangePassword("admin", "wrong", "new");
        Assert.False(ok);
        Assert.NotNull(auth.Authenticate("admin", "pw"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true);
    }

    /// <summary>UserStore が IServiceProvider 経由で VolumeService を解決するためのスタブ。</summary>
    private sealed class FakeServiceProvider : IServiceProvider
    {
        private readonly VolumeService? _volumeService;

        public FakeServiceProvider(VolumeService? volumeService = null)
        {
            _volumeService = volumeService;
        }

        public object? GetService(Type serviceType) =>
            serviceType == typeof(VolumeService) ? _volumeService : null;
    }
}
