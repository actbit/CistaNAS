using System.Net.Http.Json;
using System.Text.Json;

namespace CistaNAS.Client.Api;

/// <summary>招待機能の拡張メソッド。</summary>
public static class CistaNasApiClientInvitations
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>招待を作成する。</summary>
    public static async Task<string> CreateInvitationAsync(this CistaNasApiClient client, string targetUsername)
    {
        var http = GetHttp(client);
        var req = new { targetUsername };
        var res = await http.PostAsJsonAsync("/api/v1/e2ee/invitations", req, JsonOpts);
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("invitationId").GetString()!;
    }

    /// <summary>招待情報を取得する。</summary>
    public static async Task<InvitationInfo?> GetInvitationAsync(this CistaNasApiClient client, string invitationId)
    {
        var http = GetHttp(client);
        var res = await http.GetAsync($"/api/v1/e2ee/invitations/{Uri.EscapeDataString(invitationId)}");
        if (!res.IsSuccessStatusCode) return null;
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return new InvitationInfo
        {
            InvitationId = json.GetProperty("invitationId").GetString()!,
            InviterUsername = json.GetProperty("inviterUsername").GetString()!,
            CreatedAt = json.GetProperty("createdAt").GetDateTimeOffset(),
        };
    }

    /// <summary>招待を受け入れる。</summary>
    public static async Task AcceptInvitationAsync(this CistaNasApiClient client, string invitationId, byte[] encryptedPublicKey, byte[] nonce)
    {
        var http = GetHttp(client);
        var req = new
        {
            encryptedPublicKey = Convert.ToBase64String(encryptedPublicKey),
            nonce = Convert.ToBase64String(nonce)
        };
        var res = await http.PostAsJsonAsync($"/api/v1/e2ee/invitations/{Uri.EscapeDataString(invitationId)}/accept", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    private static HttpClient GetHttp(CistaNasApiClient client)
    {
        var field = typeof(CistaNasApiClient).GetField("_http", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?? throw new InvalidOperationException("_http フィールドが見つかりません。");
        return (HttpClient?)field.GetValue(client) ?? throw new InvalidOperationException("_http が null です。");
    }
}

/// <summary>招待情報。</summary>
public class InvitationInfo
{
    public required string InvitationId { get; set; }
    public string InviterUsername { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
}
