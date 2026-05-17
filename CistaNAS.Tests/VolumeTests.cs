using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public class VolumeTests : IDisposable
{
    private readonly string _dataRoot;
    private readonly VolumeService _vs;

    public VolumeTests()
    {
        _dataRoot = Path.Combine(Path.GetTempPath(), "cista-vol-" + Guid.NewGuid().ToString("N"));
        var opt = new CistaNasOptions
        {
            DataRoot = _dataRoot,
            Volume = new VolumeOptions { SectorSize = 512, KdfIterations = 10_000 },
        };
        _vs = new VolumeService(Options.Create(opt));
    }

    [Fact]
    public void Create_Encrypted_WithUserCreds_ReturnsMounted()
    {
        var info = _vs.Create("test-vol", "admin", "password123", encrypted: true);
        Assert.Equal("test-vol", info.Name);
        Assert.True(info.IsMounted);
        Assert.True(info.Encrypted);
        Assert.Equal("admin", info.OwnerUser);
    }

    [Fact]
    public void Create_Plain_ReturnsMountedVolume()
    {
        var info = _vs.Create("plain-vol", null, null, encrypted: false);
        Assert.Equal("plain-vol", info.Name);
        Assert.False(info.Encrypted);
    }

    [Fact]
    public void Mount_SameUser_SamePassword_Succeeds()
    {
        _vs.Create("vol-b", "admin", "correct-pw", encrypted: true);
        _vs.Lock("vol-b");

        var info = _vs.Mount("vol-b", "admin", "correct-pw");
        Assert.True(info.IsMounted);
    }

    [Fact]
    public void Mount_DifferentPassword_Fails()
    {
        _vs.Create("vol-c", "admin", "right", encrypted: true);
        _vs.Lock("vol-c");

        Assert.Throws<VolumeException>(() => _vs.Mount("vol-c", "admin", "wrong"));
    }

    [Fact]
    public void Mount_DifferentUser_Fails_EvenWithCorrectPassword()
    {
        _vs.Create("vol-d", "admin", "shared-pw", encrypted: true);
        _vs.Lock("vol-d");

        // 別ユーザーはソルトが違うので KEK が異なる → 復号失敗
        Assert.Throws<VolumeException>(() => _vs.Mount("vol-d", "other-user", "shared-pw"));
    }

    [Fact]
    public void Mount_Plain_NoPassword_Succeeds()
    {
        _vs.Create("vol-plain", null, null, encrypted: false);
        _vs.Lock("vol-plain");

        var info = _vs.Mount("vol-plain", "", null);
        Assert.True(info.IsMounted);
        Assert.False(info.Encrypted);
    }

    [Fact]
    public void Lock_ClearsMountedState()
    {
        _vs.Create("vol-e", "admin", "pw", encrypted: true);
        Assert.True(_vs.IsMounted("vol-e"));

        _vs.Lock("vol-e");
        Assert.False(_vs.IsMounted("vol-e"));
    }

    [Fact]
    public void Create_Duplicate_Throws()
    {
        _vs.Create("dup", "admin", "pw", encrypted: true);
        Assert.Throws<VolumeException>(() => _vs.Create("dup", "admin", "pw2", encrypted: true));
    }

    [Fact]
    public void ListMounted_ReturnsOnlyMounted()
    {
        _vs.Create("m1", "admin", "pw1", encrypted: true);
        _vs.Create("m2", null, null, encrypted: false);
        _vs.Lock("m1");

        var mounted = _vs.ListMounted();
        Assert.Single(mounted);
        Assert.Equal("m2", mounted[0].Name);
    }

    [Fact]
    public void GetMounted_ReturnsStream()
    {
        _vs.Create("io-test", "admin", "pw", encrypted: true);
        var (stream, header) = _vs.GetMounted("io-test");
        Assert.NotNull(stream);
        Assert.True(stream.CanRead);
        Assert.True(stream.CanWrite);
        Assert.Equal("io-test", header.Name);
        Assert.Equal("admin", header.OwnerUser);
    }

    public void Dispose()
    {
        foreach (var v in _vs.ListMounted())
        {
            try { _vs.Lock(v.Name); } catch { }
        }
        if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true);
    }
}
