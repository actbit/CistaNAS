using CistaNAS.Web.Services;
using Microsoft.Extensions.DependencyInjection;

namespace CistaNAS.Tests;

public class AuthTests : IDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly AsyncServiceScope _scope;
    private readonly AuthService _auth;
    private readonly AccountService _accountService;

    public AuthTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _scope = _sp.CreateAsyncScope();
        _auth = _scope.ServiceProvider.GetRequiredService<AuthService>();
        _accountService = _scope.ServiceProvider.GetRequiredService<AccountService>();
    }

    [Fact]
    public async Task CreateInitialAdmin_ThenAuthenticate()
    {
        Assert.False(await _accountService.HasAnyUsersAsync());
        await _accountService.CreateInitialAdminAsync("admin", "test-pw");
        Assert.True(await _accountService.HasAnyUsersAsync());

        var res = await _auth.AuthenticateAsync("admin", "test-pw");
        Assert.NotNull(res);
        Assert.Equal("Bearer", res!.TokenType);
    }

    [Fact]
    public async Task CreateInitialAdmin_Fails_WhenUsersExist()
    {
        await _accountService.CreateInitialAdminAsync("admin", "test-pw");
        await Assert.ThrowsAsync<InvalidOperationException>(() => _accountService.CreateInitialAdminAsync("admin2", "test-pw2"));
    }

    [Theory]
    [InlineData("admin", "wrong")]
    [InlineData("nobody", "test-pw")]
    [InlineData("", "")]
    public async Task Authenticate_Fails_WithBadCredentials(string user, string pw)
    {
        await _accountService.CreateInitialAdminAsync("admin", "test-pw");
        Assert.Null(await _auth.AuthenticateAsync(user, pw));
    }

    [Fact]
    public async Task IssuedToken_Validates_AndCarriesIdentity()
    {
        await _accountService.CreateInitialAdminAsync("admin", "test-pw");
        var res = (await _auth.AuthenticateAsync("admin", "test-pw"))!;

        var principal = await _auth.ValidateTokenAsync(res.AccessToken);
        Assert.NotNull(principal);
        Assert.Equal("admin", principal!.Identity?.Name);
    }

    [Fact]
    public async Task ValidateToken_Rejects_Tampered()
    {
        await _accountService.CreateInitialAdminAsync("admin", "test-pw");
        var res = (await _auth.AuthenticateAsync("admin", "test-pw"))!;
        string tampered = res.AccessToken[..^2] + (res.AccessToken[^1] == 'A' ? "BB" : "AA");
        Assert.Null(await _auth.ValidateTokenAsync(tampered));
    }

    [Fact]
    public async Task ChangePassword_Reauth_WithNewPassword()
    {
        await _accountService.CreateInitialAdminAsync("admin", "old-pw");

        bool ok = await _auth.ChangePasswordAsync("admin", "old-pw", "new-pw");
        Assert.True(ok);

        Assert.Null(await _auth.AuthenticateAsync("admin", "old-pw"));
        Assert.NotNull(await _auth.AuthenticateAsync("admin", "new-pw"));
    }

    [Fact]
    public async Task ChangePassword_WrongOld_Fails()
    {
        await _accountService.CreateInitialAdminAsync("admin", "test-pw");

        bool ok = await _auth.ChangePasswordAsync("admin", "wrong", "new-pw");
        Assert.False(ok);
        Assert.NotNull(await _auth.AuthenticateAsync("admin", "test-pw"));
    }

    public void Dispose()
    {
        _scope.Dispose();
        try { if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true); } catch { }
    }
}
