using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using Microsoft.Extensions.DependencyInjection;

namespace CistaNAS.Tests;

/// <summary>
/// 認可のハードニングに関するテスト。
/// SetUserQuota のサービス層オーナー確認（M1）と ListUsers のロール非開示（M2）を検証。
/// </summary>
public class AuthorizationHardeningTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _vs;

    public AuthorizationHardeningTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _vs = _sp.GetRequiredService<VolumeService>();
    }

    [Fact]
    public async Task SetUserQuota_NonOwner_Throws()
    {
        string vol = "quota-auth";
        await _vs.CreateAsync(vol, "owner", "pw", encrypted: false);

        await Assert.ThrowsAsync<VolumeException>(() =>
            _vs.SetUserQuotaAsync(vol, requesterUsername: "attacker", targetUsername: "owner", maxBytes: 1000));
    }

    [Fact]
    public async Task SetUserQuota_Owner_Succeeds()
    {
        string vol = "quota-ok";
        await _vs.CreateAsync(vol, "owner", "pw", encrypted: false);

        await _vs.SetUserQuotaAsync(vol, requesterUsername: "owner", targetUsername: "someone", maxBytes: 1000);
    }

    [Fact]
    public async Task ListUsers_IncludeRolesFalse_HidesRoles()
    {
        using var scope = _sp.CreateAsyncScope();
        var accountSvc = scope.ServiceProvider.GetRequiredService<AccountService>();
        await accountSvc.CreateUserAsync("alice", "password123", "admin");
        await accountSvc.CreateUserAsync("bob", "password123", "user");

        var hidden = await accountSvc.ListUserDtosAsync(includeRoles: false);
        Assert.All(hidden, u => Assert.Empty(u.Roles));

        var revealed = await accountSvc.ListUserDtosAsync(includeRoles: true);
        Assert.Contains(revealed, u => u.UserName == "alice" && u.Roles.Contains("admin"));
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var v in await _vs.ListAllAsync())
        {
            try
            {
                var header = await _vs.GetVolumeHeaderAsync(v.Name);
                await _vs.LockAsync(v.Name, header.OwnerUser);
            }
            catch (Exception) { }
        }
        try { if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true); } catch (Exception) { }
    }
}
