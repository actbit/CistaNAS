using System.Net.Http.Json;
using System.Text.Json;

namespace CistaNAS.Client.Api;

/// <summary>認証関連の拡張メソッド。</summary>
public static class CistaNasApiClientAuth
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>パスワードを変更する。</summary>
    public static async Task ChangePasswordAsync(this CistaNasApiClient client, string oldPassword, string newPassword)
    {
        var http = GetHttp(client);
        var req = new { oldPassword = oldPassword, newPassword = newPassword };
        var res = await http.PostAsJsonAsync("/api/v1/auth/change-password", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    private static HttpClient GetHttp(CistaNasApiClient client)
    {
        var field = typeof(CistaNasApiClient).GetField("_http", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?? throw new InvalidOperationException("_http フィールドが見つかりません。");
        return (HttpClient?)field.GetValue(client) ?? throw new InvalidOperationException("_http が null です。");
    }
}
