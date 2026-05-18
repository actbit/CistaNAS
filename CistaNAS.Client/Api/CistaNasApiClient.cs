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
