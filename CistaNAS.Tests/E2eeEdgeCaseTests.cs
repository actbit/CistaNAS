using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// E2EE エンドポイント（/api/v1/e2ee）のエッジケース・エラー系 E2E テスト。
/// AspireFixture（AppHost 共有）経由で実際の HTTP リクエストを通して検証する。
/// ハッピーパスは AspireHttpTests / ApiClientTests が網羅済みのため、
/// ここでは認可エラー・リソース不在・差分更新(replace)・finalize 更新に焦点を当てる。
/// </summary>
[Collection("Aspire")]
public class E2eeEdgeCaseTests(AspireFixture fixture)
{
    private HttpClient Http => fixture.Http;
    private string Token => fixture.Token;

    /// <summary>JWT を自動付与する HttpClient を作成。</summary>
    private HttpClient CreateAuthClient()
    {
        var c = new HttpClient { BaseAddress = Http.BaseAddress };
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        return c;
    }

    /// <summary>admin 所有の E2EE ボリュームを作成し、(ボリューム名, マスターキー) を返す。</summary>
    private static async Task<(string VolName, byte[] MasterKey)> CreateVolumeAsync(HttpClient c, string prefix)
    {
        string volName = $"{prefix}-{Guid.NewGuid():N}";
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(AspireFixture.Username, AspireFixture.Password, salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        CryptographicOperations.ZeroMemory(kek);

        var resp = await c.PostAsJsonAsync("/api/v1/e2ee/create-volume", new
        {
            volumeName = volName,
            username = AspireFixture.Username,
            wrappedMasterKey = new
            {
                kdf = new { algorithm = "pbkdf2-sha256", iterations = 1000, salt },
                wrappedMasterKey = new { algorithm = "aes-256-gcm", nonce, ciphertext = ct, tag },
            },
            chunkSize = 1048576,
        });
        Assert.True(resp.IsSuccessStatusCode, $"create-volume failed: {resp.StatusCode}");
        return (volName, masterKey);
    }

    /// <summary>ファイルを作成し fileId を返す。</summary>
    private static async Task<string> CreateFileAsync(HttpClient c, string vol, string name, long encLen, int chunkCount)
    {
        var resp = await c.PostAsJsonAsync($"/api/v1/e2ee/{vol}/create-file",
            new { encryptedName = name, encryptedLength = encLen, chunkCount });
        Assert.True(resp.IsSuccessStatusCode, $"create-file failed: {resp.StatusCode}");
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("fileId").GetString()!;
    }

    /// <summary>chunk-hash を取得し (hash, revision) を返す。</summary>
    private static async Task<(string? Hash, int Revision)> GetChunkHashAsync(
        HttpClient c, string vol, string fileId, int chunkIndex)
    {
        var resp = await c.GetAsync($"/api/v1/e2ee/{vol}/chunk-hash/{fileId}/{chunkIndex}");
        Assert.True(resp.IsSuccessStatusCode, $"chunk-hash failed: {resp.StatusCode}");
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
        return (json.GetProperty("hash").GetString(), json.GetProperty("revision").GetInt32());
    }

    // ---- 認可エラー ----

    /// <summary>トークン無しでは E2EE API にアクセスできない（401）。</summary>
    [Fact]
    public async Task NoAuthToken_Returns401()
    {
        using var anon = new HttpClient { BaseAddress = Http.BaseAddress };
        var resp = await anon.GetAsync("/api/v1/e2ee/any-vol/files");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ---- リソース不在 ----

    /// <summary>存在しない fileId のチャンクダウンロードは 404。</summary>
    [Fact]
    public async Task DownloadChunk_NonExistentFile_Returns404()
    {
        using var c = CreateAuthClient();
        string vol = (await CreateVolumeAsync(c, "edge-dl404")).VolName;

        var resp = await c.GetAsync($"/api/v1/e2ee/{vol}/download-chunk/nonexistent-file-id/0");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    /// <summary>存在しない fileId の削除は 404。</summary>
    [Fact]
    public async Task DeleteFile_NonExistent_Returns404()
    {
        using var c = CreateAuthClient();
        string vol = (await CreateVolumeAsync(c, "edge-del404")).VolName;

        var resp = await c.DeleteAsync($"/api/v1/e2ee/{vol}/files/nonexistent-file-id");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    /// <summary>未アップロードの chunkIndex の hash 取得は 404。</summary>
    [Fact]
    public async Task GetChunkHash_NotYetUploadedChunk_Returns404()
    {
        using var c = CreateAuthClient();
        string vol = (await CreateVolumeAsync(c, "edge-hash404")).VolName;
        string fileId = await CreateFileAsync(c, vol, "enc-missing-chunk", 100, 1);

        var resp = await c.GetAsync($"/api/v1/e2ee/{vol}/chunk-hash/{fileId}/0");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ---- 差分更新 (replace) ----

    /// <summary>replace=false で revision=0、replace=true で revision が +1 される（AES-GCM nonce 再利用回避）。
    /// 上書き後の暗号文を revision=1 で正しく復元できることも検証する。</summary>
    [Fact]
    public async Task UploadChunk_ReplaceMode_IncrementsRevision()
    {
        using var c = CreateAuthClient();
        var (vol, masterKey) = await CreateVolumeAsync(c, "edge-replace");

        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        byte[] plain = RandomNumberGenerator.GetBytes(500);

        // 初回アップロード (replace なし) → revision 0
        byte[] enc0 = E2eeCrypto.EncryptChunk(plain, fileKey, 0, fileSalt, isFirstChunk: true);
        string fileId = await CreateFileAsync(c, vol, "enc-replace", enc0.Length, 1);
        using (var content0 = new ByteArrayContent(enc0))
        {
            content0.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            var r0 = await c.PostAsync($"/api/v1/e2ee/{vol}/upload-chunk/{fileId}/0", content0);
            Assert.True(r0.IsSuccessStatusCode, $"initial upload failed: {r0.StatusCode}");
        }
        var (hash0, rev0) = await GetChunkHashAsync(c, vol, fileId, 0);
        Assert.Equal(0, rev0);
        Assert.False(string.IsNullOrEmpty(hash0));

        // 差分上書き (replace=true) → revision 1
        byte[] enc1 = E2eeCrypto.EncryptChunk(plain, fileKey, 0, fileSalt, isFirstChunk: true, revision: 1);
        using (var content1 = new ByteArrayContent(enc1))
        {
            content1.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            var r1 = await c.PostAsync($"/api/v1/e2ee/{vol}/upload-chunk/{fileId}/0?replace=true", content1);
            Assert.True(r1.IsSuccessStatusCode, $"replace upload failed: {r1.StatusCode}");
        }
        var (hash1, rev1) = await GetChunkHashAsync(c, vol, fileId, 0);
        Assert.Equal(1, rev1);

        // ダウンロードして revision=1 の暗号文を正しく復号できること
        var dl = await c.GetAsync($"/api/v1/e2ee/{vol}/download-chunk/{fileId}/0");
        Assert.True(dl.IsSuccessStatusCode);
        byte[] downloaded = await dl.Content.ReadAsByteArrayAsync();
        byte[] decrypted = E2eeCrypto.DecryptChunk(downloaded, fileKey, 0, fileSalt, revision: 1);
        Assert.Equal(plain, decrypted);

        CryptographicOperations.ZeroMemory(masterKey);
    }

    // ---- finalize ----

    /// <summary>finalize で encryptedLength が更新される。</summary>
    [Fact]
    public async Task FinalizeFile_UpdatesEncryptedLength()
    {
        using var c = CreateAuthClient();
        string vol = (await CreateVolumeAsync(c, "edge-finalize")).VolName;
        string fileId = await CreateFileAsync(c, vol, "enc-finalize", 2048, 1);

        var resp = await c.PatchAsJsonAsync($"/api/v1/e2ee/{vol}/finalize-file/{fileId}",
            new { actualEncryptedLength = 1500 });
        Assert.True(resp.IsSuccessStatusCode, $"finalize failed: {resp.StatusCode}");

        var listResp = await c.GetAsync($"/api/v1/e2ee/{vol}/files");
        Assert.True(listResp.IsSuccessStatusCode);
        var list = await listResp.Content.ReadFromJsonAsync<JsonElement>();
        var files = list.GetProperty("files").EnumerateArray().ToArray();
        Assert.Single(files);
        Assert.Equal(1500, files[0].GetProperty("encryptedLength").GetInt64());
    }
}
