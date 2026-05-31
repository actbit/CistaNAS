using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace CistaNAS.Client.Api;

/// <summary>
/// CistaNAS サーバーの /api/v1/e2ee エンドポイントにアクセスする HTTP クライアント。
/// </summary>
public sealed class CistaNasApiClient
{
    private readonly HttpClient _http;
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public CistaNasApiClient(HttpClient http)
    {
        _http = http;
    }

    public void SetToken(string token)
    {
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    // ---- 認証 ----

    public async Task<string> LoginAsync(string username, string password)
    {
        var res = await _http.PostAsJsonAsync("/api/v1/auth/login", new { username, password }, JsonOpts);
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("accessToken").GetString()!;
    }

    // ---- E2EE ボリューム ----

    public async Task CreateVolumeAsync(string volumeName, string username,
        byte[] wrappedNonce, byte[] wrappedCt, byte[] wrappedTag,
        byte[] kdfSalt, int kdfIterations, int chunkSize = 1048576)
    {
        var req = new
        {
            volumeName,
            username,
            wrappedMasterKey = new
            {
                kdf = new { algorithm = "pbkdf2-sha256", iterations = kdfIterations, salt = kdfSalt },
                wrappedMasterKey = new
                {
                    algorithm = "aes-256-gcm",
                    nonce = wrappedNonce,
                    ciphertext = wrappedCt,
                    tag = wrappedTag
                }
            },
            chunkSize
        };
        var res = await _http.PostAsJsonAsync("/api/v1/e2ee/create-volume", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    public async Task MountAsync(string volumeName)
    {
        var res = await _http.PostAsJsonAsync($"/api/v1/e2ee/{volumeName}/mount", new { });
        res.EnsureSuccessStatusCode();
    }

    public async Task<WrappedKeyInfo> GetWrappedKeyAsync(string volumeName, string username)
    {
        var res = await _http.GetAsync($"/api/v1/e2ee/{volumeName}/wrapped-key/{username}");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();

        var kdf = json.GetProperty("kdf");
        var wk = json.GetProperty("wrappedMasterKey");

        return new WrappedKeyInfo
        {
            KdfAlgorithm = kdf.GetProperty("algorithm").GetString()!,
            KdfIterations = kdf.GetProperty("iterations").GetInt32(),
            KdfSalt = Convert.FromBase64String(kdf.GetProperty("salt").GetString()!),
            WrappedNonce = Convert.FromBase64String(wk.GetProperty("nonce").GetString()!),
            WrappedCiphertext = Convert.FromBase64String(wk.GetProperty("ciphertext").GetString()!),
            WrappedTag = Convert.FromBase64String(wk.GetProperty("tag").GetString()!),
            ChunkSize = json.TryGetProperty("chunkSize", out var cs) ? cs.GetInt32() : 1048576,
        };
    }

    public async Task<string> CreateFileAsync(string volumeName, string encryptedName, long encryptedLength, int chunkCount)
    {
        var req = new { encryptedName, encryptedLength, chunkCount };
        var res = await _http.PostAsJsonAsync($"/api/v1/e2ee/{volumeName}/create-file", req, JsonOpts);
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("fileId").GetString()!;
    }

    public async Task UploadChunkAsync(string volumeName, string fileId, int chunkIndex, byte[] data)
    {
        var content = new ByteArrayContent(data);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        var res = await _http.PostAsync(
            $"/api/v1/e2ee/{volumeName}/upload-chunk/{fileId}/{chunkIndex}", content);
        res.EnsureSuccessStatusCode();
    }

    public async Task<byte[]> DownloadChunkAsync(string volumeName, string fileId, int chunkIndex)
    {
        var res = await _http.GetAsync($"/api/v1/e2ee/{volumeName}/download-chunk/{fileId}/{chunkIndex}");
        res.EnsureSuccessStatusCode();
        return await res.Content.ReadAsByteArrayAsync();
    }

    public async Task FinalizeFileAsync(string volumeName, string fileId, long actualLength)
    {
        var req = new { actualEncryptedLength = actualLength };
        var res = await _http.PatchAsJsonAsync($"/api/v1/e2ee/{volumeName}/finalize-file/{fileId}", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    public async Task DeleteFileAsync(string volumeName, string fileId)
    {
        var res = await _http.DeleteAsync($"/api/v1/e2ee/{volumeName}/files/{fileId}");
        res.EnsureSuccessStatusCode();
    }

    public async Task<List<E2eeFileEntry>> ListFilesAsync(string volumeName)
    {
        var res = await _http.GetAsync($"/api/v1/e2ee/{volumeName}/files");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        var files = json.GetProperty("files");
        var result = new List<E2eeFileEntry>();
        foreach (var f in files.EnumerateArray())
        {
            result.Add(new E2eeFileEntry
            {
                FileId = f.GetProperty("fileId").GetString()!,
                EncryptedName = f.GetProperty("encryptedName").GetString()!,
                EncryptedLength = f.GetProperty("encryptedLength").GetInt64(),
                ChunkCount = f.GetProperty("chunkCount").GetInt32(),
                CreatedAt = f.GetProperty("createdAt").GetDateTimeOffset(),
                ModifiedAt = f.GetProperty("modifiedAt").GetDateTimeOffset(),
            });
        }
        return result;
    }

    public async Task<List<VolumeListItem>> ListVolumesAsync()
    {
        var res = await _http.GetAsync("/api/v1/volumes");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        var result = new List<VolumeListItem>();
        if (json.ValueKind == JsonValueKind.Array)
        {
            foreach (var v in json.EnumerateArray())
            {
                result.Add(new VolumeListItem
                {
                    Name = v.GetProperty("name").GetString()!,
                    Encrypted = v.TryGetProperty("encrypted", out var enc) && enc.GetBoolean(),
                    EncryptionMode = v.TryGetProperty("encryptionMode", out var mode) ? mode.GetString() ?? "server" : "server",
                    IsMounted = v.TryGetProperty("isMounted", out var mnt) && mnt.GetBoolean(),
                    OwnerUser = v.TryGetProperty("ownerUser", out var owner) ? owner.GetString() ?? "" : "",
                });
            }
        }
        return result;
    }

    public async Task<VolumeStats> GetVolumeStatsAsync(string volumeName)
    {
        var res = await _http.GetAsync($"/api/v1/e2ee/{volumeName}/stats");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return new VolumeStats
        {
            TotalUsedBytes = json.GetProperty("totalUsedBytes").GetInt64(),
            UserUsedBytes = json.GetProperty("userUsedBytes").GetInt64(),
            UserQuotaBytes = json.GetProperty("userQuotaBytes").GetInt64(),
            TotalFiles = json.GetProperty("totalFiles").GetInt32(),
            UserFiles = json.GetProperty("userFiles").GetInt32(),
        };
    }
}

public class E2eeFileEntry
{
    public required string FileId { get; set; }
    public required string EncryptedName { get; set; }
    public long EncryptedLength { get; set; }
    public int ChunkCount { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }
}

public class VolumeListItem
{
    public required string Name { get; set; }
    public bool Encrypted { get; set; }
    public string EncryptionMode { get; set; } = "server";
    public bool IsMounted { get; set; }
    public string OwnerUser { get; set; } = "";
}

public class VolumeStats
{
    public long TotalUsedBytes { get; set; }
    public long UserUsedBytes { get; set; }
    public long UserQuotaBytes { get; set; }
    public int TotalFiles { get; set; }
    public int UserFiles { get; set; }
}

public class WrappedKeyInfo
{
    public required string KdfAlgorithm { get; set; }
    public required int KdfIterations { get; set; }
    public required byte[] KdfSalt { get; set; }
    public required byte[] WrappedNonce { get; set; }
    public required byte[] WrappedCiphertext { get; set; }
    public required byte[] WrappedTag { get; set; }
    public int ChunkSize { get; set; } = 1048576;
}
