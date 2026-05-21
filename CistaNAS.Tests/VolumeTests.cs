using System.Security.Cryptography;
using CistaNAS.Client.Crypto;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public class VolumeTests : IDisposable
{
    private readonly string _dataRoot;
    private readonly VolumeService _vs;
    private readonly VolumeOptions _volOpts;

    public VolumeTests()
    {
        _dataRoot = Path.Combine(Path.GetTempPath(), "cista-vol-" + Guid.NewGuid().ToString("N"));
        _volOpts = new VolumeOptions { SectorSize = 512, KdfIterations = 10_000 };
        var opt = new CistaNasOptions { DataRoot = _dataRoot, Volume = _volOpts };
        var io = Options.Create(opt);
        var storage = new LocalStorageProvider(_dataRoot);
        var metaStore = new VolumeMetadataStore(storage);
        var gs = new GroupStore(storage, io, new ServiceCollection().BuildServiceProvider());
        var sp = new ServiceCollection().AddLogging().BuildServiceProvider();
        var us = new UserStore(storage, io, sp.GetRequiredService<ILogger<UserStore>>(), sp);
        _vs = new VolumeService(io, gs, us, metaStore);
    }

    [Fact]
    public void Create_Encrypted_PopulatesUserKeys()
    {
        var info = _vs.Create("test-vol", "alice", "password123", encrypted: true);
        Assert.Equal("test-vol", info.Name);
        Assert.True(info.IsMounted);
        Assert.True(info.Encrypted);
        Assert.Equal("alice", info.OwnerUser);
        Assert.Contains("alice", info.AuthorizedUsers);
    }

    [Fact]
    public void Create_Plain_NoUserKeys()
    {
        var info = _vs.Create("plain-vol", null, null, encrypted: false);
        Assert.False(info.Encrypted);
        Assert.Empty(info.AuthorizedUsers);
    }

    [Fact]
    public void Mount_SameUser_SamePassword_Succeeds()
    {
        _vs.Create("vol-b", "alice", "pw", encrypted: true);
        _vs.Lock("vol-b");
        var info = _vs.Mount("vol-b", "alice", "pw");
        Assert.True(info.IsMounted);
    }

    [Fact]
    public void Mount_WrongPassword_Fails()
    {
        _vs.Create("vol-c", "alice", "right", encrypted: true);
        _vs.Lock("vol-c");
        Assert.Throws<VolumeException>(() => _vs.Mount("vol-c", "alice", "wrong"));
    }

    [Fact]
    public void Mount_DifferentUser_Fails()
    {
        _vs.Create("vol-d", "alice", "shared-pw", encrypted: true);
        _vs.Lock("vol-d");
        Assert.Throws<VolumeException>(() => _vs.Mount("vol-d", "bob", "shared-pw"));
    }

    [Fact]
    public void GrantAccess_SecondUser_CanMount()
    {
        _vs.Create("shared", "alice", "alice-pw", encrypted: true);
        _vs.Lock("shared");

        // alice が bob に共有
        _vs.GrantAccess("shared", "alice", "alice-pw", "bob", "bob-pw");

        // bob がマウント
        var info = _vs.Mount("shared", "bob", "bob-pw");
        Assert.True(info.IsMounted);
        Assert.Contains("alice", info.AuthorizedUsers);
        Assert.Contains("bob", info.AuthorizedUsers);
    }

    [Fact]
    public void RevokeAccess_RemovesUser()
    {
        _vs.Create("rev-test", "alice", "alice-pw", encrypted: true);
        _vs.GrantAccess("rev-test", "alice", "alice-pw", "bob", "bob-pw");
        _vs.RevokeAccess("rev-test", "alice", "bob");

        _vs.Lock("rev-test");
        Assert.Throws<VolumeException>(() => _vs.Mount("rev-test", "bob", "bob-pw"));
    }

    [Fact]
    public void RevokeAccess_Owner_Throws()
    {
        _vs.Create("owner-test", "alice", "pw", encrypted: true);
        Assert.Throws<VolumeException>(() => _vs.RevokeAccess("owner-test", "alice", "alice"));
    }

    [Fact]
    public void RewrapAllForUser_PasswordChange()
    {
        _vs.Create("rewrap", "alice", "old-pw", encrypted: true);
        _vs.Lock("rewrap");

        // パスワード変更（再ラップ）
        _vs.RewrapAllForUser("alice", "old-pw", "new-pw");

        // 古いパスワードでマウント失敗
        Assert.Throws<VolumeException>(() => _vs.Mount("rewrap", "alice", "old-pw"));

        // 新しいパスワードでマウント成功
        var info = _vs.Mount("rewrap", "alice", "new-pw");
        Assert.True(info.IsMounted);
    }

    [Fact]
    public void RewrapAllForUser_OnlyAffectsTargetUser()
    {
        _vs.Create("multi", "alice", "alice-pw", encrypted: true);
        _vs.GrantAccess("multi", "alice", "alice-pw", "bob", "bob-pw");
        _vs.Lock("multi");

        // alice のパスワード変更
        _vs.RewrapAllForUser("alice", "alice-pw", "alice-new");

        // bob は影響なし
        var info = _vs.Mount("multi", "bob", "bob-pw");
        Assert.True(info.IsMounted);
    }

    [Fact]
    public void ListForUser_ReturnsOnlyAccessible()
    {
        _vs.Create("a1", "alice", "pw", encrypted: true);
        _vs.Create("b1", "bob", "pw", encrypted: true);

        var aliceList = _vs.ListForUser("alice");
        Assert.Single(aliceList);
        Assert.Equal("a1", aliceList[0].Name);
    }

    [Fact]
    public void HasAccess_ReturnsCorrectly()
    {
        _vs.Create("acc", "alice", "pw", encrypted: true);
        Assert.True(_vs.HasAccess("acc", "alice"));
        Assert.False(_vs.HasAccess("acc", "bob"));
    }

    [Fact]
    public void Lock_ClearsMountedState()
    {
        _vs.Create("lock-test", "alice", "pw", encrypted: true);
        Assert.True(_vs.IsMounted("lock-test"));
        _vs.Lock("lock-test");
        Assert.False(_vs.IsMounted("lock-test"));
    }

    public void Dispose()
    {
        foreach (var v in _vs.ListAll())
        {
            try { _vs.Lock(v.Name); } catch { }
        }
        if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true);
    }

    // ---- 追加テスト ----

    [Fact]
    public void Create_GroupPrefix_Throws()
    {
        Assert.Throws<VolumeException>(() =>
            _vs.Create("group__test", "alice", "pw", encrypted: true));
    }

    [Fact]
    public void Create_InvalidChars_Throws()
    {
        Assert.Throws<VolumeException>(() =>
            _vs.Create("bad|name", "alice", "pw", encrypted: true));
    }

    [Fact]
    public void Create_TooLong_Throws()
    {
        string longName = new('a', 65);
        Assert.Throws<VolumeException>(() =>
            _vs.Create(longName, "alice", "pw", encrypted: true));
    }

    [Fact]
    public void DoubleMount_Throws()
    {
        _vs.Create("dm", "alice", "pw", encrypted: true);
        Assert.Throws<VolumeException>(() => _vs.Mount("dm", "alice", "pw"));
    }

    [Fact]
    public void Lock_NotMounted_Throws()
    {
        Assert.Throws<VolumeException>(() => _vs.Lock("nonexistent"));
    }

    [Fact]
    public void DeleteVolume_RemovesDirectory()
    {
        _vs.Create("to-delete", "alice", "pw", encrypted: true);
        Assert.True(Directory.Exists(Path.Combine(_dataRoot, "to-delete")));

        _vs.DeleteVolume("to-delete");
        Assert.False(Directory.Exists(Path.Combine(_dataRoot, "to-delete")));
        Assert.False(_vs.IsMounted("to-delete"));
    }

    [Fact]
    public void MountE2ee_Success()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek("alice", "pw", salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);

        _vs.CreateE2ee("e2ee-mount", "alice", new VolumeHeader.UserWrappedKey
        {
            Kdf = new() { Algorithm = "pbkdf2-sha256", Iterations = 1000, Salt = salt },
            WrappedMasterKey = new() { Algorithm = "aes-256-gcm", Nonce = nonce, Ciphertext = ct, Tag = tag },
        });

        _vs.Lock("e2ee-mount");
        var info = _vs.MountE2ee("e2ee-mount", "alice");
        Assert.True(info.IsMounted);
    }

    [Fact]
    public void MountE2ee_WrongUser_Throws()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek("alice", "pw", salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);

        _vs.CreateE2ee("e2ee-mount2", "alice", new VolumeHeader.UserWrappedKey
        {
            Kdf = new() { Algorithm = "pbkdf2-sha256", Iterations = 1000, Salt = salt },
            WrappedMasterKey = new() { Algorithm = "aes-256-gcm", Nonce = nonce, Ciphertext = ct, Tag = tag },
        });

        _vs.Lock("e2ee-mount2");
        Assert.Throws<VolumeException>(() => _vs.MountE2ee("e2ee-mount2", "bob"));
    }

    [Fact]
    public void GrantGroupAccess_E2eeVolume_Throws()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek("alice", "pw", salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);

        var gs = new GroupStore(new LocalStorageProvider(_dataRoot),
            Options.Create(new CistaNasOptions { DataRoot = _dataRoot }),
            new ServiceCollection().BuildServiceProvider());
        gs.CreateGroup("testg", "alice");

        _vs.CreateE2ee("e2ee-group", "alice", new VolumeHeader.UserWrappedKey
        {
            Kdf = new() { Algorithm = "pbkdf2-sha256", Iterations = 1000, Salt = salt },
            WrappedMasterKey = new() { Algorithm = "aes-256-gcm", Nonce = nonce, Ciphertext = ct, Tag = tag },
        });

        Assert.Throws<VolumeException>(() =>
            _vs.GrantGroupAccess("e2ee-group", "alice", "testg"));
    }
}
