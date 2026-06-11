using System.Net.Http.Json;
using System.Text.Json;

namespace CistaNAS.Client.Api;

/// <summary>暗号化設定の拡張メソッド。</summary>
public static class CistaNasApiClientSettings
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>暗号化設定を取得する。</summary>
    public static async Task<EncryptionSettingsInfo> GetEncryptionSettingsAsync(this CistaNasApiClient client)
    {
        var http = GetHttp(client);
        var res = await http.GetAsync("/api/v1/settings/encryption");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return new EncryptionSettingsInfo
        {
            DefaultEncryptionMode = json.GetProperty("defaultEncryptionMode").GetString() ?? "server",
            E2eeChunkSize = json.GetProperty("e2eeChunkSize").GetInt32(),
            KdfIterations = json.GetProperty("kdfIterations").GetInt32(),
            SectorSize = json.GetProperty("sectorSize").GetInt32(),
        };
    }

    /// <summary>暗号化設定を保存する。</summary>
    public static async Task SaveEncryptionSettingsAsync(this CistaNasApiClient client, EncryptionSettingsInfo settings)
    {
        var http = GetHttp(client);
        var req = new
        {
            defaultEncryptionMode = settings.DefaultEncryptionMode,
            e2eeChunkSize = settings.E2eeChunkSize,
            kdfIterations = settings.KdfIterations,
            sectorSize = settings.SectorSize,
        };
        var res = await http.PutAsJsonAsync("/api/v1/settings/encryption", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    private static HttpClient GetHttp(CistaNasApiClient client)
    {
        var field = typeof(CistaNasApiClient).GetField("_http", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?? throw new InvalidOperationException("_http フィールドが見つかりません。");
        return (HttpClient?)field.GetValue(client) ?? throw new InvalidOperationException("_http が null です。");
    }
}

/// <summary>暗号化設定。</summary>
public class EncryptionSettingsInfo
{
    public string DefaultEncryptionMode { get; set; } = "server";
    public int E2eeChunkSize { get; set; } = 1048576;
    public int KdfIterations { get; set; } = 600_000;
    public int SectorSize { get; set; } = 4096;
}
