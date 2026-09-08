using System.Net.Http.Json;

namespace CistaNAS.Wasm.Services;

/// <summary>暗号化設定 API クライアント。</summary>
public sealed class EncryptionSettingsClient
{
    private readonly HttpClient _http;

    public EncryptionSettingsClient(HttpClient http) => _http = http;

    /// <summary>暗号化設定を取得。</summary>
    public async Task<EncryptionSettings> GetAsync()
    {
        var result = await _http.GetFromJsonAsync<EncryptionSettings>("/api/v1/settings/encryption");
        return result ?? new EncryptionSettings();
    }

    /// <summary>暗号化設定を保存。</summary>
    public async Task SaveAsync(EncryptionSettings settings)
    {
        var response = await _http.PutAsync("/api/v1/settings/encryption",
            JsonContent.Create(settings));
        response.EnsureSuccessStatusCode();
    }
}

/// <summary>暗号化設定。Kdf* は新規鍵導出スペック（KdfAlgorithm == "argon2id" は Argon2id+PBKDF2 合成、"argon2id-raw" は Argon2id 単独）。</summary>
public sealed class EncryptionSettings
{
    public string DefaultEncryptionMode { get; set; } = "server";
    public int E2eeChunkSize { get; set; } = 1048576;
    /// <summary>"argon2id"（合成、既定）or "argon2id-raw"（Argon2id 単独）。</summary>
    public string KdfAlgorithm { get; set; } = "argon2id";
    /// <summary>合成 KDF の後段 PBKDF2 反復数（argon2id-raw では不使用）。</summary>
    public int KdfIterations { get; set; } = 600_000;
    public int KdfMemoryKiB { get; set; } = 65536;
    public int KdfTimeCost { get; set; } = 4;
    public int KdfParallelism { get; set; } = 4;
    public int SectorSize { get; set; } = 4096;
}
