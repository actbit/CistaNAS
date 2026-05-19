using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Client.Crypto;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public class EcdhTests : IDisposable
{
    private readonly string _dataRoot;
    private readonly VolumeService _vs;
    private readonly UserStore _userStore;

    public EcdhTests()
    {
        _dataRoot = Path.Combine(Path.GetTempPath(), "cista-ecdh-" + Guid.NewGuid().ToString("N"));
        var opt = new CistaNasOptions
        {
            DataRoot = _dataRoot,
            Volume = new VolumeOptions { SectorSize = 512, KdfIterations = 10_000 },
        };
        var io = Options.Create(opt);
        var gs = new GroupStore(io, new ServiceCollection().BuildServiceProvider());
        var sp = new ServiceCollection().AddLogging().BuildServiceProvider();
        _userStore = new UserStore(io, sp.GetRequiredService<ILogger<UserStore>>(), sp);
        _vs = new VolumeService(io, gs, _userStore);
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
    public void CreateGroupE2ee_Succeeds()
    {
        var wrappedKey = CreatePasswordWrappedKey("alice", "pw", out _);
        var info = _vs.CreateGroupE2ee("team-a", "alice", wrappedKey);

        Assert.Equal("group__team-a", info.Name);
        Assert.True(info.Encrypted);
        Assert.Equal("e2ee", info.EncryptionMode);
        Assert.Contains("alice", info.AuthorizedUsers);
    }

    [Fact]
    public void CreateGroupE2ee_Duplicate_Throws()
    {
        var wk = CreatePasswordWrappedKey("alice", "pw", out _);
        _vs.CreateGroupE2ee("dup-vol", "alice", wk);
        Assert.Throws<VolumeException>(() => _vs.CreateGroupE2ee("dup-vol", "alice", wk));
    }

    // ---- AddE2eeWrappedKey (ECDH) ----

    [Fact]
    public void AddE2eeWrappedKey_Ecdh_IncreasesAuthorizedUsers()
    {
        var wk = CreatePasswordWrappedKey("alice", "pw", out _);
        var info = _vs.CreateGroupE2ee("share-vol", "alice", wk);

        var ecdhKey = CreateEcdhWrappedKey();
        _vs.AddE2eeWrappedKey(info.Name, "alice", "bob", ecdhKey);

        var list = _vs.ListForUser("bob");
        Assert.Single(list);
        Assert.Equal(info.Name, list[0].Name);
    }

    // ---- UserWrapTypes ----

    [Fact]
    public void UserWrapTypes_Reflects_WrapTypes()
    {
        var wk = CreatePasswordWrappedKey("alice", "pw", out _);
        var info = _vs.CreateGroupE2ee("wrap-vol", "alice", wk);

        var ecdhKey = CreateEcdhWrappedKey();
        _vs.AddE2eeWrappedKey(info.Name, "alice", "bob", ecdhKey);

        var volInfo = _vs.GetVolumeInfo(info.Name);
        Assert.NotNull(volInfo!.UserWrapTypes);
        Assert.Equal("password", volInfo.UserWrapTypes["alice"]);
        Assert.Equal("ecdh", volInfo.UserWrapTypes["bob"]);
    }

    // ---- GetVolumeInfo / GetVolumeHeader ----

    [Fact]
    public void GetVolumeInfo_Existing_ReturnsInfo()
    {
        _vs.Create("info-vol", "alice", "pw", encrypted: true);
        var info = _vs.GetVolumeInfo("info-vol");
        Assert.NotNull(info);
        Assert.Equal("info-vol", info.Name);
    }

    [Fact]
    public void GetVolumeInfo_NonExistent_ReturnsNull()
    {
        Assert.Null(_vs.GetVolumeInfo("no-such-vol"));
    }

    [Fact]
    public void GetVolumeHeader_ReturnsHeader()
    {
        _vs.Create("hdr-vol", "alice", "pw", encrypted: true);
        var hdr = _vs.GetVolumeHeader("hdr-vol");
        Assert.Equal("alice", hdr.OwnerUser);
    }

    // ---- RevokeAccess removes wrapped key ----

    [Fact]
    public void RevokeAccess_EcdhUser_RemovesFromList()
    {
        var wk = CreatePasswordWrappedKey("alice", "pw", out _);
        var info = _vs.CreateGroupE2ee("revoke-vol", "alice", wk);

        var ecdhKey = CreateEcdhWrappedKey();
        _vs.AddE2eeWrappedKey(info.Name, "alice", "bob", ecdhKey);

        _vs.RevokeAccess(info.Name, "alice", "bob");

        var bobList = _vs.ListForUser("bob");
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

    public void Dispose()
    {
        foreach (var v in _vs.ListAll())
        {
            try { _vs.Lock(v.Name); } catch { }
        }
        if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true);
    }
}
