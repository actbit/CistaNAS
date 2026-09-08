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
        var http = client._http;
        var res = await http.GetAsync("/api/v1/settings/encryption");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return new EncryptionSettingsInfo
        {
            DefaultEncryptionMode = json.GetProperty("defaultEncryptionMode").GetString() ?? "server",
            E2eeChunkSize = json.GetProperty("e2eeChunkSize").GetInt32(),
            KdfAlgorithm = json.TryGetProperty("kdfAlgorithm", out var ka) && ka.ValueKind == JsonValueKind.String
                ? ka.GetString() ?? KdfInfo.Argon2id : KdfInfo.Argon2id,
            KdfIterations = json.GetProperty("kdfIterations").GetInt32(),
            KdfMemoryKiB = json.TryGetProperty("kdfMemoryKiB", out var mm) && mm.ValueKind == JsonValueKind.Number ? mm.GetInt32() : 65536,
            KdfTimeCost = json.TryGetProperty("kdfTimeCost", out var tc) && tc.ValueKind == JsonValueKind.Number ? tc.GetInt32() : 4,
            KdfParallelism = json.TryGetProperty("kdfParallelism", out var pl) && pl.ValueKind == JsonValueKind.Number ? pl.GetInt32() : 4,
            SectorSize = json.GetProperty("sectorSize").GetInt32(),
        };
    }

    /// <summary>暗号化設定を保存する。</summary>
    public static async Task SaveEncryptionSettingsAsync(this CistaNasApiClient client, EncryptionSettingsInfo settings)
    {
        var http = client._http;
        var req = new
        {
            defaultEncryptionMode = settings.DefaultEncryptionMode,
            e2eeChunkSize = settings.E2eeChunkSize,
            kdfAlgorithm = settings.KdfAlgorithm,
            kdfIterations = settings.KdfIterations,
            kdfMemoryKiB = settings.KdfMemoryKiB,
            kdfTimeCost = settings.KdfTimeCost,
            kdfParallelism = settings.KdfParallelism,
            sectorSize = settings.SectorSize,
        };
        var res = await http.PutAsJsonAsync("/api/v1/settings/encryption", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }
}

/// <summary>暗号化設定。Kdf* は新規鍵導出スペック（KdfAlgorithm == "argon2id" は Argon2id+PBKDF2 合成、"argon2id-raw" は Argon2id 単独）。</summary>
public class EncryptionSettingsInfo
{
    public string DefaultEncryptionMode { get; set; } = "server";
    public int E2eeChunkSize { get; set; } = 1048576;
    /// <summary>"argon2id"（合成、既定）or "argon2id-raw"（Argon2id 単独）。</summary>
    public string KdfAlgorithm { get; set; } = KdfInfo.Argon2id;
    /// <summary>合成 KDF の後段 PBKDF2 反復数（argon2id-raw では不使用）。</summary>
    public int KdfIterations { get; set; } = 600_000;
    public int KdfMemoryKiB { get; set; } = 65536;
    public int KdfTimeCost { get; set; } = 4;
    public int KdfParallelism { get; set; } = 4;
    public int SectorSize { get; set; } = 4096;
}
