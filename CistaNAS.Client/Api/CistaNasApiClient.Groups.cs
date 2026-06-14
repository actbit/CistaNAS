using System.Net.Http.Json;
using System.Text.Json;

namespace CistaNAS.Client.Api;

/// <summary>グループ管理の拡張メソッド。</summary>
public static class CistaNasApiClientGroups
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>ユーザーのグループ一覧を取得する。</summary>
    public static async Task<List<GroupInfo>> ListGroupsAsync(this CistaNasApiClient client)
    {
        var http = GetHttp(client);
        var res = await http.GetAsync("/api/v1/groups/");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        var result = new List<GroupInfo>();
        foreach (var g in json.EnumerateArray())
        {
            var members = new List<string>();
            if (g.TryGetProperty("members", out var membersEl))
            {
                foreach (var m in membersEl.EnumerateArray())
                    members.Add(m.GetProperty("username").GetString() ?? "");
            }

            result.Add(new GroupInfo
            {
                GroupName = g.GetProperty("groupName").GetString()!,
                CreatedAt = g.GetProperty("createdAt").GetDateTimeOffset(),
                OwnerUsername = g.TryGetProperty("ownerUser", out var ownerEl)
                    ? ownerEl.GetString() ?? ""
                    : g.TryGetProperty("ownerUsername", out var owner2) ? owner2.GetString() ?? "" : "",
                Members = members,
            });
        }
        return result;
    }

    /// <summary>グループを作成する。</summary>
    public static async Task CreateGroupAsync(this CistaNasApiClient client, string groupName)
    {
        var http = GetHttp(client);
        var req = new { groupName };
        var res = await http.PostAsJsonAsync("/api/v1/groups/", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>グループを削除する。</summary>
    public static async Task DeleteGroupAsync(this CistaNasApiClient client, string groupName)
    {
        var http = GetHttp(client);
        var res = await http.DeleteAsync($"/api/v1/groups/{Uri.EscapeDataString(groupName)}");
        res.EnsureSuccessStatusCode();
    }

    /// <summary>グループにメンバーを追加する。</summary>
    public static async Task AddGroupMemberAsync(this CistaNasApiClient client, string groupName, string username)
    {
        var http = GetHttp(client);
        var req = new { username };
        var res = await http.PostAsJsonAsync($"/api/v1/groups/{Uri.EscapeDataString(groupName)}/members", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>グループからメンバーを削除する。</summary>
    public static async Task RemoveGroupMemberAsync(this CistaNasApiClient client, string groupName, string username)
    {
        var http = GetHttp(client);
        var res = await http.DeleteAsync($"/api/v1/groups/{Uri.EscapeDataString(groupName)}/members/{Uri.EscapeDataString(username)}");
        res.EnsureSuccessStatusCode();
    }

    private static HttpClient GetHttp(CistaNasApiClient client)
    {
        var field = typeof(CistaNasApiClient).GetField("_http", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?? throw new InvalidOperationException("_http フィールドが見つかりません。");
        return (HttpClient?)field.GetValue(client) ?? throw new InvalidOperationException("_http が null です。");
    }
}

/// <summary>グループ情報。</summary>
public class GroupInfo
{
    public required string GroupName { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public string OwnerUsername { get; set; } = "";
    public List<string> Members { get; set; } = [];
}
