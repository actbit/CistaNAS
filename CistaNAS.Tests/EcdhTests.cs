using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Client.Crypto;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public class EcdhTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _vs;

    public EcdhTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _vs = _sp.GetRequiredService<VolumeService>();
    }

    // ---- VolumeHeader.UserWrappedKey シリアライズ ----

    [Fact]
    public void UserWrappedKey_WrapType_Ecdh_Serializes()
    {
        byte[] ephPubKey = RandomNumberGenerator.GetBytes(65);
        var key = new VolumeHeader.UserWrappedKey
        {
            WrapType = "ecdh",
            Kdf = new() { Algorithm = "none" },
            WrappedMasterKey = new()
            {
                Algorithm = "aes-256-gcm",
                Nonce = RandomNumberGenerator.GetBytes(12),
                Ciphertext = RandomNumberGenerator.GetBytes(32),
                Tag = RandomNumberGenerator.GetBytes(16),
            },
            EphemeralPublicKey = ephPubKey,
        };

        string json = JsonSerializer.Serialize(key);
        var deserialized = JsonSerializer.Deserialize<VolumeHeader.UserWrappedKey>(json);

        Assert.Equal("ecdh", deserialized!.WrapType);
        Assert.Equal(ephPubKey, deserialized.EphemeralPublicKey);
    }

    [Fact]
    public void UserWrappedKey_DefaultWrapType_IsPassword()
    {
        var key = new VolumeHeader.UserWrappedKey();
        Assert.Equal("password", key.WrapType);
        Assert.Null(key.EphemeralPublicKey);
    }

    // ---- CreateGroupE2ee ----

    [Fact]
    public async Task CreateGroupE2ee_Succeeds()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("team-a", "alice");
        var wrappedKey = CreatePasswordWrappedKey("alice", "pw", out _);
        var info = await _vs.CreateGroupE2eeAsync("team-a", "alice", wrappedKey);

        Assert.Equal("group__team-a", info.Name);
        Assert.True(info.Encrypted);
        Assert.Equal("e2ee", info.EncryptionMode);
        Assert.Contains("alice", info.AuthorizedUsers);
    }

    [Fact]
    public async Task CreateGroupE2ee_Duplicate_Throws()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("dup-vol", "alice");
        var wk = CreatePasswordWrappedKey("alice", "pw", out _);
        await _vs.CreateGroupE2eeAsync("dup-vol", "alice", wk);
        await Assert.ThrowsAsync<VolumeException>(() => _vs.CreateGroupE2eeAsync("dup-vol", "alice", wk));
    }

    // ---- AddE2eeWrappedKey (ECDH) ----

    [Fact]
    public async Task AddE2eeWrappedKey_Ecdh_IncreasesAuthorizedUsers()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("share-vol", "alice");
        var wk = CreatePasswordWrappedKey("alice", "pw", out _);
        var info = await _vs.CreateGroupE2eeAsync("share-vol", "alice", wk);

        var ecdhKey = CreateEcdhWrappedKey();
        await _vs.AddE2eeWrappedKeyAsync(info.Name, "alice", "bob", ecdhKey);

        var list = await _vs.ListForUserAsync("bob");
        Assert.Single(list);
        Assert.Equal(info.Name, list[0].Name);
    }

    // ---- UserWrapTypes ----

    [Fact]
    public async Task UserWrapTypes_Reflects_WrapTypes()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("wrap-vol", "alice");
        var wk = CreatePasswordWrappedKey("alice", "pw", out _);
        var info = await _vs.CreateGroupE2eeAsync("wrap-vol", "alice", wk);

        var ecdhKey = CreateEcdhWrappedKey();
        await _vs.AddE2eeWrappedKeyAsync(info.Name, "alice", "bob", ecdhKey);

        var volInfo = await _vs.GetVolumeInfoAsync(info.Name);
        Assert.NotNull(volInfo!.UserWrapTypes);
        Assert.Equal("password", volInfo.UserWrapTypes["alice"]);
        Assert.Equal("ecdh", volInfo.UserWrapTypes["bob"]);
    }

    // ---- GetVolumeInfo / GetVolumeHeader ----

    [Fact]
    public async Task GetVolumeInfo_Existing_ReturnsInfo()
    {
        await _vs.CreateAsync("info-vol", "alice", "pw", encrypted: true);
        var info = await _vs.GetVolumeInfoAsync("info-vol");
        Assert.NotNull(info);
        Assert.Equal("info-vol", info.Name);
    }

    [Fact]
    public async Task GetVolumeInfo_NonExistent_ReturnsNull()
    {
        Assert.Null(await _vs.GetVolumeInfoAsync("no-such-vol"));
    }

    [Fact]
    public async Task GetVolumeHeader_ReturnsHeader()
    {
        await _vs.CreateAsync("hdr-vol", "alice", "pw", encrypted: true);
        var hdr = await _vs.GetVolumeHeaderAsync("hdr-vol");
        Assert.Equal("alice", hdr.OwnerUser);
    }

    // ---- RevokeAccess removes wrapped key ----

    [Fact]
    public async Task RevokeAccess_EcdhUser_RemovesFromList()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("revoke-vol", "alice");
        var wk = CreatePasswordWrappedKey("alice", "pw", out _);
        var info = await _vs.CreateGroupE2eeAsync("revoke-vol", "alice", wk);

        var ecdhKey = CreateEcdhWrappedKey();
        await _vs.AddE2eeWrappedKeyAsync(info.Name, "alice", "bob", ecdhKey);

        await _vs.RevokeAccessAsync(info.Name, "alice", "bob");

        var bobList = await _vs.ListForUserAsync("bob");
        Assert.Empty(bobList);
    }

    // ---- InvitationService ----

    [Fact]
    public void InvitationService_CreateAndFind()
    {
        var svc = new InvitationService();
        var record = svc.Create("alice", "bob");

        Assert.Equal("alice", record.InviterUsername);
        Assert.Equal("bob", record.TargetUsername);

        var found = svc.Find(record.InvitationId);
        Assert.NotNull(found);
        Assert.Equal(record.InvitationId, found!.InvitationId);
    }

    [Fact]
    public void InvitationService_SetAcceptedData()
    {
        var svc = new InvitationService();
        var record = svc.Create("alice", "bob");

        svc.SetAcceptedData(record.InvitationId, "pubkey-data", "nonce123");

        var found = svc.Find(record.InvitationId);
        Assert.NotNull(found);
        Assert.Equal("pubkey-data", found!.EncryptedPublicKey);
        Assert.Equal("nonce123", found.Nonce);
        Assert.True(found.AcceptedAt.HasValue);
    }

    [Fact]
    public void InvitationService_Remove()
    {
        var svc = new InvitationService();
        var record = svc.Create("alice", "bob");
        svc.Remove(record.InvitationId);
        Assert.Null(svc.Find(record.InvitationId));
    }

    // ---- Helpers ----

    private VolumeHeader.UserWrappedKey CreatePasswordWrappedKey(string user, string password, out byte[] masterKey)
    {
        masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(user, password, salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);

        return new VolumeHeader.UserWrappedKey
        {
            WrapType = "password",
            Kdf = new() { Algorithm = "pbkdf2-sha256", Iterations = 1000, Salt = salt },
            WrappedMasterKey = new()
            {
                Algorithm = "aes-256-gcm",
                Nonce = nonce,
                Ciphertext = ct,
                Tag = tag,
            },
        };
    }

    private static VolumeHeader.UserWrappedKey CreateEcdhWrappedKey()
    {
        return new VolumeHeader.UserWrappedKey
        {
            WrapType = "ecdh",
            Kdf = new() { Algorithm = "none" },
            EphemeralPublicKey = RandomNumberGenerator.GetBytes(65),
            WrappedMasterKey = new()
            {
                Algorithm = "aes-256-gcm",
                Nonce = RandomNumberGenerator.GetBytes(12),
                Ciphertext = RandomNumberGenerator.GetBytes(32),
                Tag = RandomNumberGenerator.GetBytes(16),
            },
        };
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
