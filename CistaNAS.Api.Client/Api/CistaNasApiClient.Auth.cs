using System.Net.Http.Json;
using System.Text.Json;

namespace CistaNAS.Client.Api;

/// <summary>認証関連の拡張メソッド。</summary>
public static class CistaNasApiClientAuth
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>初期ユーザーが存在するか確認する。</summary>
    public static async Task<bool> HasUsersAsync(this CistaNasApiClient client)
    {
        var res = await client._http.GetAsync("/api/v1/auth/has-users");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("hasUsers").GetBoolean();
    }

    /// <summary>初期管理者を作成する（初回セットアップ）。成功後は LoginAsync でログインする。</summary>
    public static async Task RunInitialSetupAsync(this CistaNasApiClient client, string username, string password)
    {
        var req = new { username, password };
        var res = await client._http.PostAsJsonAsync("/api/v1/auth/setup", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>パスワードを変更する。</summary>
    public static async Task ChangePasswordAsync(this CistaNasApiClient client, string oldPassword, string newPassword)
    {
        var http = client._http;
        var req = new { oldPassword = oldPassword, newPassword = newPassword };
        var res = await http.PostAsJsonAsync("/api/v1/auth/change-password", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }
}
