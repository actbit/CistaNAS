using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using Microsoft.Extensions.DependencyInjection;

namespace CistaNAS.Tests;

public class GroupTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _vs;

    public GroupTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _vs = _sp.GetRequiredService<VolumeService>();
    }

    // ---- GroupService CRUD ----

    [Fact]
    public async Task CreateGroup_AddsOwnerAsMember()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("team-a", "alice");
        var g = await gs.FindAsync("team-a");
        Assert.NotNull(g);
        Assert.Equal("alice", g.OwnerUser);
        Assert.Contains(g.Members, m => m.Username == "alice");
    }

    [Fact]
    public async Task CreateGroup_Duplicate_Throws()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("team-b", "alice");
        await Assert.ThrowsAsync<InvalidOperationException>(() => gs.CreateGroupAsync("team-b", "bob"));
    }

    [Fact]
    public async Task DeleteGroup_OwnerCanDelete()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("team-c", "alice");
        await gs.DeleteGroupAsync("team-c", "alice");
        Assert.Null(await gs.FindAsync("team-c"));
    }

    [Fact]
    public async Task DeleteGroup_NonOwner_Throws()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("team-d", "alice");
        await Assert.ThrowsAsync<InvalidOperationException>(() => gs.DeleteGroupAsync("team-d", "bob"));
    }

    [Fact]
    public async Task AddMember_OwnerCanAdd()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("team-e", "alice");
        await gs.AddMemberAsync("team-e", "alice", "bob");
        Assert.True(await gs.IsMemberAsync("team-e", "bob"));
    }

    [Fact]
    public async Task AddMember_Duplicate_Throws()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("team-f", "alice");
        await gs.AddMemberAsync("team-f", "alice", "bob");
        await Assert.ThrowsAsync<InvalidOperationException>(() => gs.AddMemberAsync("team-f", "alice", "bob"));
    }

    [Fact]
    public async Task RemoveMember_OwnerCanRemove()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("team-g", "alice");
        await gs.AddMemberAsync("team-g", "alice", "bob");
        await gs.RemoveMemberAsync("team-g", "alice", "bob");
        Assert.False(await gs.IsMemberAsync("team-g", "bob"));
    }

    [Fact]
    public async Task RemoveMember_CannotRemoveOwner()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("team-h", "alice");
        await Assert.ThrowsAsync<InvalidOperationException>(() => gs.RemoveMemberAsync("team-h", "alice", "alice"));
    }

    [Fact]
    public async Task GetGroupsForUser_ReturnsCorrectGroups()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("ga", "alice");
        await gs.CreateGroupAsync("gb", "bob");
        await gs.AddMemberAsync("gb", "bob", "alice");

        var aliceGroups = await gs.GetGroupsForUserAsync("alice");
        Assert.Equal(2, aliceGroups.Count);
    }

    [Fact]
    public async Task RemoveUserFromAllGroups()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();
        await gs.CreateGroupAsync("ra", "alice");
        await gs.CreateGroupAsync("rb", "bob");
        await gs.AddMemberAsync("ra", "alice", "charlie");
        await gs.AddMemberAsync("rb", "bob", "charlie");

        await gs.RemoveUserFromAllGroupsAsync("charlie");
        Assert.False(await gs.IsMemberAsync("ra", "charlie"));
        Assert.False(await gs.IsMemberAsync("rb", "charlie"));
    }

    // ---- Volume group access ----

    [Fact]
    public async Task GrantGroupAccess_MemberCanSeeVolume()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();

        await _vs.CreateAsync("grp-vol1", "alice", "pw", encrypted: true);
        await gs.CreateGroupAsync("team1", "alice");
        await gs.AddMemberAsync("team1", "alice", "bob");

        await _vs.GrantGroupAccessAsync("grp-vol1", "alice", "team1");

        var bobList = await _vs.ListForUserAsync("bob");
        Assert.Single(bobList);
        Assert.Equal("grp-vol1", bobList[0].Name);
    }

    [Fact]
    public async Task RevokeGroupAccess_MemberCannotSeeVolume()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();

        await _vs.CreateAsync("grp-vol2", "alice", "pw", encrypted: true);
        await gs.CreateGroupAsync("team2", "alice");
        await gs.AddMemberAsync("team2", "alice", "bob");

        await _vs.GrantGroupAccessAsync("grp-vol2", "alice", "team2");
        await _vs.RevokeGroupAccessAsync("grp-vol2", "alice", "team2");

        var bobList = await _vs.ListForUserAsync("bob");
        Assert.Empty(bobList);
    }

    [Fact]
    public async Task GrantGroupAccess_NonOwner_Throws()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();

        await _vs.CreateAsync("grp-vol3", "alice", "pw", encrypted: true);
        await gs.CreateGroupAsync("team3", "alice");
        await Assert.ThrowsAsync<VolumeException>(() => _vs.GrantGroupAccessAsync("grp-vol3", "bob", "team3"));
    }

    [Fact]
    public async Task DeleteGroup_RemovesVolumeAccess()
    {
        using var scope = _sp.CreateAsyncScope();
        var gs = scope.ServiceProvider.GetRequiredService<GroupService>();

        await _vs.CreateAsync("grp-vol4", "alice", "pw", encrypted: true);
        await gs.CreateGroupAsync("team4", "alice");
        await gs.AddMemberAsync("team4", "alice", "bob");
        await _vs.GrantGroupAccessAsync("grp-vol4", "alice", "team4");

        await gs.DeleteGroupAsync("team4", "alice");

        var bobList = await _vs.ListForUserAsync("bob");
        Assert.Empty(bobList);
    }

    // ---- Home volume naming ----

    [Fact]
    public async Task Create_HomePrefix_Throws()
    {
        await Assert.ThrowsAsync<VolumeException>(() => _vs.CreateAsync("home__test", "alice", "pw", encrypted: true));
    }

    [Fact]
    public async Task Create_NormalName_Succeeds()
    {
        var info = await _vs.CreateAsync("regular-vol", "alice", "pw", encrypted: true);
        Assert.Equal("regular-vol", info.Name);
        Assert.False(info.IsHome);
    }

    [Fact]
    public async Task ListForUser_IncludesHomeVolume()
    {
        await _vs.CreateInternalAsync("home__alice", "alice", null, encrypted: false);
        var list = await _vs.ListForUserAsync("alice");
        Assert.Single(list);
        Assert.True(list[0].IsHome);
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
