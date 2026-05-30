using System.Security.Cryptography;
using CistaNAS.Client.Crypto;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public class VolumeTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _vs;

    public VolumeTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _vs = _sp.GetRequiredService<VolumeService>();
    }

    [Fact]
    public async Task Create_Encrypted_PopulatesUserKeys()
    {
        var info = await _vs.CreateAsync("test-vol", "alice", "password123", encrypted: true);
        Assert.Equal("test-vol", info.Name);
        Assert.True(info.IsMounted);
        Assert.True(info.Encrypted);
        Assert.Equal("alice", info.OwnerUser);
        Assert.Contains("alice", info.AuthorizedUsers);
    }

    [Fact]
    public async Task Create_Plain_NoUserKeys()
    {
        var info = await _vs.CreateAsync("plain-vol", null, null, encrypted: false);
        Assert.False(info.Encrypted);
        Assert.Empty(info.AuthorizedUsers);
    }

    [Fact]
    public async Task Mount_SameUser_SamePassword_Succeeds()
    {
        await _vs.CreateAsync("vol-b", "alice", "pw", encrypted: true);
        await _vs.LockAsync("vol-b", "alice");
        var info = await _vs.MountAsync("vol-b", "alice", "pw");
        Assert.True(info.IsMounted);
    }

    [Fact]
    public async Task Mount_WrongPassword_Fails()
    {
        await _vs.CreateAsync("vol-c", "alice", "right", encrypted: true);
        await _vs.LockAsync("vol-c", "alice");
        await Assert.ThrowsAsync<VolumeException>(() => _vs.MountAsync("vol-c", "alice", "wrong"));
    }

    [Fact]
    public async Task Mount_DifferentUser_Fails()
    {
        await _vs.CreateAsync("vol-d", "alice", "shared-pw", encrypted: true);
        await _vs.LockAsync("vol-d", "alice");
        await Assert.ThrowsAsync<VolumeException>(() => _vs.MountAsync("vol-d", "bob", "shared-pw"));
    }

    [Fact]
    public async Task GrantAccess_SecondUser_CanMount()
    {
        await _vs.CreateAsync("shared", "alice", "alice-pw", encrypted: true);
        await _vs.LockAsync("shared", "alice");

        await _vs.GrantAccessAsync("shared", "alice", "alice-pw", "bob", "bob-pw");

        var info = await _vs.MountAsync("shared", "bob", "bob-pw");
        Assert.True(info.IsMounted);
        Assert.Contains("alice", info.AuthorizedUsers);
        Assert.Contains("bob", info.AuthorizedUsers);
    }

    [Fact]
    public async Task RevokeAccess_RemovesUser()
    {
        await _vs.CreateAsync("rev-test", "alice", "alice-pw", encrypted: true);
        await _vs.GrantAccessAsync("rev-test", "alice", "alice-pw", "bob", "bob-pw");
        await _vs.RevokeAccessAsync("rev-test", "alice", "bob");

        await _vs.LockAsync("rev-test", "alice");
        await Assert.ThrowsAsync<VolumeException>(() => _vs.MountAsync("rev-test", "bob", "bob-pw"));
    }

    [Fact]
    public async Task RevokeAccess_Owner_Throws()
    {
        await _vs.CreateAsync("owner-test", "alice", "pw", encrypted: true);
        await Assert.ThrowsAsync<VolumeException>(() => _vs.RevokeAccessAsync("owner-test", "alice", "alice"));
    }

    [Fact]
    public async Task RewrapAllForUser_PasswordChange()
    {
        await _vs.CreateAsync("rewrap", "alice", "old-pw", encrypted: true);
        await _vs.LockAsync("rewrap", "alice");

        await _vs.RewrapAllForUserAsync("alice", "old-pw", "new-pw");

        await Assert.ThrowsAsync<VolumeException>(() => _vs.MountAsync("rewrap", "alice", "old-pw"));

        var info = await _vs.MountAsync("rewrap", "alice", "new-pw");
        Assert.True(info.IsMounted);
    }

    [Fact]
    public async Task RewrapAllForUser_OnlyAffectsTargetUser()
    {
        await _vs.CreateAsync("multi", "alice", "alice-pw", encrypted: true);
        await _vs.GrantAccessAsync("multi", "alice", "alice-pw", "bob", "bob-pw");
        await _vs.LockAsync("multi", "alice");

        await _vs.RewrapAllForUserAsync("alice", "alice-pw", "alice-new");

        var info = await _vs.MountAsync("multi", "bob", "bob-pw");
        Assert.True(info.IsMounted);
    }

    [Fact]
    public async Task ListForUser_ReturnsOnlyAccessible()
    {
        await _vs.CreateAsync("a1", "alice", "pw", encrypted: true);
        await _vs.CreateAsync("b1", "bob", "pw", encrypted: true);

        var aliceList = await _vs.ListForUserAsync("alice");
        Assert.Single(aliceList);
        Assert.Equal("a1", aliceList[0].Name);
    }

    [Fact]
    public async Task HasAccess_ReturnsCorrectly()
    {
        await _vs.CreateAsync("acc", "alice", "pw", encrypted: true);
        Assert.True(await _vs.HasAccessAsync("acc", "alice"));
        Assert.False(await _vs.HasAccessAsync("acc", "bob"));
    }

    [Fact]
    public async Task Lock_ClearsMountedState()
    {
        await _vs.CreateAsync("lock-test", "alice", "pw", encrypted: true);
        Assert.True(_vs.IsMounted("lock-test"));
        await _vs.LockAsync("lock-test", "alice");
        Assert.False(_vs.IsMounted("lock-test"));
    }

    [Fact]
    public async Task Create_GroupPrefix_Throws()
    {
        await Assert.ThrowsAsync<VolumeException>(() =>
            _vs.CreateAsync("group__test", "alice", "pw", encrypted: true));
    }

    [Fact]
    public async Task Create_InvalidChars_Throws()
    {
        await Assert.ThrowsAsync<VolumeException>(() =>
            _vs.CreateAsync("bad|name", "alice", "pw", encrypted: true));
    }

    [Fact]
    public async Task Create_TooLong_Throws()
    {
        string longName = new('a', 65);
        await Assert.ThrowsAsync<VolumeException>(() =>
            _vs.CreateAsync(longName, "alice", "pw", encrypted: true));
    }

    [Fact]
    public async Task DoubleMount_Throws()
    {
        await _vs.CreateAsync("dm", "alice", "pw", encrypted: true);
        await Assert.ThrowsAsync<VolumeException>(() => _vs.MountAsync("dm", "alice", "pw"));
    }

    [Fact]
    public async Task Lock_NotMounted_Throws()
    {
        await Assert.ThrowsAsync<VolumeException>(() => _vs.LockAsync("nonexistent", "alice"));
    }

    [Fact]
    public async Task DeleteVolume_RemovesDirectory()
    {
        await _vs.CreateAsync("to-delete", "alice", "pw", encrypted: true);
        Assert.True(Directory.Exists(Path.Combine(_dataRoot, "to-delete")));

        await _vs.DeleteVolumeAsync("to-delete");
        Assert.False(Directory.Exists(Path.Combine(_dataRoot, "to-delete")));
        Assert.False(_vs.IsMounted("to-delete"));
    }

    [Fact]
    public async Task MountE2ee_Success()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek("alice", "pw", salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);

        await _vs.CreateE2eeAsync("e2ee-mount", "alice", new VolumeHeader.UserWrappedKey
        {
            Kdf = new() { Algorithm = "pbkdf2-sha256", Iterations = 1000, Salt = salt },
            WrappedMasterKey = new() { Algorithm = "aes-256-gcm", Nonce = nonce, Ciphertext = ct, Tag = tag },
        });

        await _vs.LockAsync("e2ee-mount", "alice");
        var info = await _vs.MountE2eeAsync("e2ee-mount", "alice");
        Assert.True(info.IsMounted);
    }

    [Fact]
    public async Task MountE2ee_WrongUser_Throws()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek("alice", "pw", salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);

        await _vs.CreateE2eeAsync("e2ee-mount2", "alice", new VolumeHeader.UserWrappedKey
        {
            Kdf = new() { Algorithm = "pbkdf2-sha256", Iterations = 1000, Salt = salt },
            WrappedMasterKey = new() { Algorithm = "aes-256-gcm", Nonce = nonce, Ciphertext = ct, Tag = tag },
        });

        await _vs.LockAsync("e2ee-mount2", "alice");
        await Assert.ThrowsAsync<VolumeException>(() => _vs.MountE2eeAsync("e2ee-mount2", "bob"));
    }

    [Fact]
    public async Task GrantGroupAccess_E2eeVolume_Throws()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek("alice", "pw", salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);

        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("testg", "alice");

        await _vs.CreateE2eeAsync("e2ee-group", "alice", new VolumeHeader.UserWrappedKey
        {
            Kdf = new() { Algorithm = "pbkdf2-sha256", Iterations = 1000, Salt = salt },
            WrappedMasterKey = new() { Algorithm = "aes-256-gcm", Nonce = nonce, Ciphertext = ct, Tag = tag },
        });

        await Assert.ThrowsAsync<VolumeException>(() =>
            _vs.GrantGroupAccessAsync("e2ee-group", "alice", "testg"));
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
