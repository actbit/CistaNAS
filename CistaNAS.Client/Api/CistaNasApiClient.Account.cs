using System.Net.Http.Json;
using System.Text.Json;

namespace CistaNAS.Client.Api;

/// <summary>アカウント管理の拡張メソッド。</summary>
public static class CistaNasApiClientAccount
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>ユーザーが存在するか確認する。</summary>
    public static async Task<bool> HasAnyUsersAsync(this CistaNasApiClient client)
    {
        var http = GetHttp(client);
        var res = await http.GetAsync("/api/v1/auth/has-users");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("hasUsers").GetBoolean();
    }

    /// <summary>初期セットアップを実行する（初回のみ）。</summary>
    public static async Task<bool> SetupAsync(this CistaNasApiClient client, string username, string password)
    {
        var http = GetHttp(client);
        var req = new { username, password };
        var res = await http.PostAsJsonAsync("/api/v1/auth/setup", req, JsonOpts);
        if (res.StatusCode == System.Net.HttpStatusCode.Conflict) return false;
        res.EnsureSuccessStatusCode();
        return true;
    }

    /// <summary>ユーザー一覧を取得する（admin）。</summary>
    public static async Task<List<UserWithRoles>> ListUsersAsync(this CistaNasApiClient client)
    {
        var http = GetHttp(client);
        var res = await http.GetAsync("/api/v1/account/users");
        if (!res.IsSuccessStatusCode) return [];
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        var result = new List<UserWithRoles>();
        foreach (var u in json.EnumerateArray())
        {
            var roles = new List<string>();
            if (u.TryGetProperty("roles", out var rolesEl))
            {
                foreach (var r in rolesEl.EnumerateArray())
                    roles.Add(r.GetString() ?? "");
            }
            result.Add(new UserWithRoles
            {
                UserName = u.GetProperty("userName").GetString()!,
                Roles = roles,
            });
        }
        return result;
    }

    /// <summary>ユーザーを作成する（admin）。</summary>
    public static async Task CreateUserAsync(this CistaNasApiClient client, string username, string password, string role = "user")
    {
        var http = GetHttp(client);
        var req = new { username, password, role };
        var res = await http.PostAsJsonAsync("/api/v1/account/users", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>ユーザーを削除する（admin）。</summary>
    public static async Task DeleteUserAsync(this CistaNasApiClient client, string username)
    {
        var http = GetHttp(client);
        var res = await http.DeleteAsync($"/api/v1/account/users/{Uri.EscapeDataString(username)}");
        res.EnsureSuccessStatusCode();
    }

    private static HttpClient GetHttp(CistaNasApiClient client)
    {
        var field = typeof(CistaNasApiClient).GetField("_http", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?? throw new InvalidOperationException("_http フィールドが見つかりません。");
        return (HttpClient?)field.GetValue(client) ?? throw new InvalidOperationException("_http が null です。");
    }
}

/// <summary>ユーザー情報（ロール付き）。</summary>
public class UserWithRoles
{
    public required string UserName { get; set; }
    public List<string> Roles { get; set; } = [];
}
