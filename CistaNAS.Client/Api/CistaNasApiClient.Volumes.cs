using System.Net.Http.Json;
using System.Text.Json;

namespace CistaNAS.Client.Api;

/// <summary>ボリューム操作の拡張メソッド。</summary>
public static class CistaNasApiClientVolumes
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>通常ボリュームを作成する。</summary>
    public static async Task<VolumeInfo> CreateVolumeAsync(this CistaNasApiClient client, string name, string username, string? password = null, bool encrypted = true)
    {
        var http = GetHttp(client);
        var req = new { name, username, password = (string?)null, encrypted };
        if (encrypted) req = new { name, username, password = password!, encrypted };
        var res = await http.PostAsJsonAsync("/api/v1/volumes", req, JsonOpts);
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return ParseVolumeInfo(json);
    }

    /// <summary>ボリュームをマウントする。</summary>
    public static async Task<VolumeInfo> MountVolumeAsync(this CistaNasApiClient client, string name, string password)
    {
        var http = GetHttp(client);
        var req = new { password };
        var res = await http.PostAsJsonAsync($"/api/v1/volumes/{Uri.EscapeDataString(name)}/mount", req, JsonOpts);
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return ParseVolumeInfo(json);
    }

    /// <summary>ボリュームをロック（アンマウント）する。</summary>
    public static async Task LockVolumeAsync(this CistaNasApiClient client, string name)
    {
        var http = GetHttp(client);
        var res = await http.PostAsJsonAsync($"/api/v1/volumes/{Uri.EscapeDataString(name)}/lock", new { }, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>ボリュームを削除する。</summary>
    public static async Task DeleteVolumeAsync(this CistaNasApiClient client, string name)
    {
        var http = GetHttp(client);
        var res = await http.DeleteAsync($"/api/v1/volumes/{Uri.EscapeDataString(name)}");
        res.EnsureSuccessStatusCode();
    }

    /// <summary>ボリュームにユーザーアクセス権を付与する。</summary>
    public static async Task GrantAccessAsync(this CistaNasApiClient client, string name, string granterPassword, string targetUsername, string targetPassword)
    {
        var http = GetHttp(client);
        var req = new
        {
            granterPassword,
            targetUsername,
            targetPassword
        };
        var res = await http.PostAsJsonAsync($"/api/v1/volumes/{Uri.EscapeDataString(name)}/grant", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>ボリュームからユーザーアクセス権を剥奪する。</summary>
    public static async Task RevokeAccessAsync(this CistaNasApiClient client, string name, string targetUsername)
    {
        var http = GetHttp(client);
        var req = new { targetUsername };
        var res = await http.PostAsJsonAsync($"/api/v1/volumes/{Uri.EscapeDataString(name)}/revoke", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>ボリュームにグループアクセス権を付与する。</summary>
    public static async Task GrantGroupAccessAsync(this CistaNasApiClient client, string name, string groupName)
    {
        var http = GetHttp(client);
        var req = new { groupName };
        var res = await http.PostAsJsonAsync($"/api/v1/volumes/{Uri.EscapeDataString(name)}/grant-group", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>ボリュームからグループアクセス権を剥奪する。</summary>
    public static async Task RevokeGroupAccessAsync(this CistaNasApiClient client, string name, string groupName)
    {
        var http = GetHttp(client);
        var req = new { groupName };
        var res = await http.PostAsJsonAsync($"/api/v1/volumes/{Uri.EscapeDataString(name)}/revoke-group", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    private static VolumeInfo ParseVolumeInfo(JsonElement json)
    {
        return new VolumeInfo
        {
            Name = json.GetProperty("name").GetString()!,
            Encrypted = json.TryGetProperty("encrypted", out var enc) && enc.GetBoolean(),
            EncryptionMode = json.TryGetProperty("encryptionMode", out var mode) ? mode.GetString() ?? "server" : "server",
            CipherAlgorithm = json.TryGetProperty("cipherAlgorithm", out var cipher) ? cipher.GetString() ?? "aes-256-xts" : "aes-256-xts",
            KeySize = json.TryGetProperty("keySize", out var keySize) ? keySize.GetInt32() : 256,
            IsMounted = json.TryGetProperty("isMounted", out var mnt) && mnt.GetBoolean(),
            OwnerUser = json.TryGetProperty("ownerUser", out var owner) ? owner.GetString() ?? "" : "",
        };
    }

    private static HttpClient GetHttp(CistaNasApiClient client)
    {
        var field = typeof(CistaNasApiClient).GetField("_http", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?? throw new InvalidOperationException("_http フィールドが見つかりません。");
        return (HttpClient?)field.GetValue(client) ?? throw new InvalidOperationException("_http が null です。");
    }
}

/// <summary>ボリューム情報。</summary>
public class VolumeInfo
{
    public required string Name { get; set; }
    public bool Encrypted { get; set; }
    public string EncryptionMode { get; set; } = "server";
    public string CipherAlgorithm { get; set; } = "aes-256-xts";
    public int KeySize { get; set; } = 256;
    public bool IsMounted { get; set; }
    public string OwnerUser { get; set; } = "";
}
