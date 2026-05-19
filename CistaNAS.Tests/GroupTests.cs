using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public class GroupTests : IDisposable
{
    private readonly string _dataRoot;
    private readonly GroupStore _gs;
    private readonly VolumeService _vs;

    public GroupTests()
    {
        _dataRoot = Path.Combine(Path.GetTempPath(), "cista-group-" + Guid.NewGuid().ToString("N"));
        var opt = new CistaNasOptions
        {
            DataRoot = _dataRoot,
            Volume = new VolumeOptions { SectorSize = 512, KdfIterations = 10_000 },
        };
        var io = Options.Create(opt);
        var sp = new ServiceCollection()
            .AddSingleton(_ => io)
            .AddSingleton<GroupStore>()
            .AddSingleton<VolumeService>()
            .BuildServiceProvider();

        _gs = sp.GetRequiredService<GroupStore>();
        _vs = sp.GetRequiredService<VolumeService>();
    }

    // ---- GroupStore CRUD ----

    [Fact]
    public void CreateGroup_AddsOwnerAsMember()
    {
        _gs.CreateGroup("team-a", "alice");
        var g = _gs.Find("team-a");
        Assert.NotNull(g);
        Assert.Equal("alice", g.OwnerUser);
        Assert.Contains("alice", g.Members);
    }

    [Fact]
    public void CreateGroup_Duplicate_Throws()
    {
        _gs.CreateGroup("team-b", "alice");
        Assert.Throws<InvalidOperationException>(() => _gs.CreateGroup("team-b", "bob"));
    }

    [Fact]
    public void DeleteGroup_OwnerCanDelete()
    {
        _gs.CreateGroup("team-c", "alice");
        _gs.DeleteGroup("team-c", "alice");
        Assert.Null(_gs.Find("team-c"));
    }

    [Fact]
    public void DeleteGroup_NonOwner_Throws()
    {
        _gs.CreateGroup("team-d", "alice");
        Assert.Throws<InvalidOperationException>(() => _gs.DeleteGroup("team-d", "bob"));
    }

    [Fact]
    public void AddMember_OwnerCanAdd()
    {
        _gs.CreateGroup("team-e", "alice");
        _gs.AddMember("team-e", "alice", "bob");
        Assert.True(_gs.IsMember("team-e", "bob"));
    }

    [Fact]
    public void AddMember_Duplicate_Throws()
    {
        _gs.CreateGroup("team-f", "alice");
        _gs.AddMember("team-f", "alice", "bob");
        Assert.Throws<InvalidOperationException>(() => _gs.AddMember("team-f", "alice", "bob"));
    }

    [Fact]
    public void RemoveMember_OwnerCanRemove()
    {
        _gs.CreateGroup("team-g", "alice");
        _gs.AddMember("team-g", "alice", "bob");
        _gs.RemoveMember("team-g", "alice", "bob");
        Assert.False(_gs.IsMember("team-g", "bob"));
    }

    [Fact]
    public void RemoveMember_CannotRemoveOwner()
    {
        _gs.CreateGroup("team-h", "alice");
        Assert.Throws<InvalidOperationException>(() => _gs.RemoveMember("team-h", "alice", "alice"));
    }

    [Fact]
    public void GetGroupsForUser_ReturnsCorrectGroups()
    {
        _gs.CreateGroup("ga", "alice");
        _gs.CreateGroup("gb", "bob");
        _gs.AddMember("gb", "bob", "alice");

        var aliceGroups = _gs.GetGroupsForUser("alice");
        Assert.Equal(2, aliceGroups.Count);
    }

    [Fact]
    public void RemoveUserFromAllGroups()
    {
        _gs.CreateGroup("ra", "alice");
        _gs.CreateGroup("rb", "bob");
        _gs.AddMember("ra", "alice", "charlie");
        _gs.AddMember("rb", "bob", "charlie");

        _gs.RemoveUserFromAllGroups("charlie");
        Assert.False(_gs.IsMember("ra", "charlie"));
        Assert.False(_gs.IsMember("rb", "charlie"));
    }

    // ---- Volume group access ----

    [Fact]
    public void GrantGroupAccess_MemberCanSeeVolume()
    {
        _vs.Create("grp-vol1", "alice", "pw", encrypted: true);
        _gs.CreateGroup("team1", "alice");
        _gs.AddMember("team1", "alice", "bob");

        _vs.GrantGroupAccess("grp-vol1", "alice", "team1");

        var bobList = _vs.ListForUser("bob");
        Assert.Single(bobList);
        Assert.Equal("grp-vol1", bobList[0].Name);
    }

    [Fact]
    public void RevokeGroupAccess_MemberCannotSeeVolume()
    {
        _vs.Create("grp-vol2", "alice", "pw", encrypted: true);
        _gs.CreateGroup("team2", "alice");
        _gs.AddMember("team2", "alice", "bob");

        _vs.GrantGroupAccess("grp-vol2", "alice", "team2");
        _vs.RevokeGroupAccess("grp-vol2", "alice", "team2");

        var bobList = _vs.ListForUser("bob");
        Assert.Empty(bobList);
    }

    [Fact]
    public void GrantGroupAccess_NonOwner_Throws()
    {
        _vs.Create("grp-vol3", "alice", "pw", encrypted: true);
        _gs.CreateGroup("team3", "alice");
        Assert.Throws<VolumeException>(() => _vs.GrantGroupAccess("grp-vol3", "bob", "team3"));
    }

    [Fact]
    public void DeleteGroup_RemovesVolumeAccess()
    {
        _vs.Create("grp-vol4", "alice", "pw", encrypted: true);
        _gs.CreateGroup("team4", "alice");
        _gs.AddMember("team4", "alice", "bob");
        _vs.GrantGroupAccess("grp-vol4", "alice", "team4");

        _gs.DeleteGroup("team4", "alice");

        var bobList = _vs.ListForUser("bob");
        Assert.Empty(bobList);
    }

    // ---- Home volume naming ----

    [Fact]
    public void Create_HomePrefix_Throws()
    {
        Assert.Throws<VolumeException>(() => _vs.Create("home__test", "alice", "pw", encrypted: true));
    }

    [Fact]
    public void Create_NormalName_Succeeds()
    {
        var info = _vs.Create("regular-vol", "alice", "pw", encrypted: true);
        Assert.Equal("regular-vol", info.Name);
        Assert.False(info.IsHome);
    }

    [Fact]
    public void ListForUser_IncludesHomeVolume()
    {
        _vs.CreateInternal("home__alice", "alice", null, encrypted: false);
        var list = _vs.ListForUser("alice");
        Assert.Single(list);
        Assert.True(list[0].IsHome);
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
