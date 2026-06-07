using System.Net.Http.Json;

namespace CistaNAS.Wasm.Services;

/// <summary>グループ管理 API クライアント。</summary>
public sealed class GroupApiClient
{
    private readonly HttpClient _http;

    public GroupApiClient(HttpClient http) => _http = http;

    /// <summary>グループ一覧。</summary>
    public async Task<IReadOnlyList<GroupEntity>> ListAsync()
    {
        var result = await _http.GetFromJsonAsync<List<GroupEntity>>("/api/v1/groups");
        return result ?? [];
    }

    /// <summary>全グループ一覧（admin 用、メンバー情報付き）。</summary>
    public async Task<IReadOnlyList<GroupEntity>> ListGroupsAsync()
    {
        var result = await _http.GetFromJsonAsync<List<GroupEntity>>("/api/v1/groups");
        return result ?? [];
    }

    /// <summary>グループ作成。</summary>
    public async Task CreateAsync(string groupName)
    {
        var response = await _http.PostAsJsonAsync("/api/v1/groups", new { GroupName = groupName });
        response.EnsureSuccessStatusCode();
    }

    /// <summary>グループ削除。</summary>
    public async Task DeleteAsync(string groupName)
    {
        var response = await _http.DeleteAsync($"/api/v1/groups/{Uri.EscapeDataString(groupName)}");
        response.EnsureSuccessStatusCode();
    }

    /// <summary>メンバー追加。</summary>
    public async Task AddMemberAsync(string groupName, string username)
    {
        var response = await _http.PostAsJsonAsync(
            $"/api/v1/groups/{Uri.EscapeDataString(groupName)}/members",
            new { Username = username });
        response.EnsureSuccessStatusCode();
    }

    /// <summary>メンバー削除。</summary>
    public async Task RemoveMemberAsync(string groupName, string username)
    {
        var response = await _http.DeleteAsync(
            $"/api/v1/groups/{Uri.EscapeDataString(groupName)}/members/{Uri.EscapeDataString(username)}");
        response.EnsureSuccessStatusCode();
    }
}

/// <summary>グループエンティティ。</summary>
public sealed class GroupEntity
{
    public string GroupName { get; set; } = "";
    public string OwnerUser { get; set; } = "";
    public List<GroupMember> Members { get; set; } = [];
    public List<string> MemberNames => Members.Select(m => m.Username).ToList();
}

/// <summary>グループメンバー。</summary>
public sealed class GroupMember
{
    public string Username { get; set; } = "";
}
