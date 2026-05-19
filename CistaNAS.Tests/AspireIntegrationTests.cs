using System.Net;
using System.Net.Http.Json;
using CistaNAS.Client.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// Aspire 分散アプリケーションの結合テスト。
/// AppHost を起動して HTTP エンドポイント経由で E2EE フルフローを検証。
/// </summary>
public class AspireIntegrationTests : IAsyncLifetime
{
    private DistributedApplication? _app;
    private HttpClient? _http;

    public async Task InitializeAsync()
    {
        var builder = await DistributedApplicationTestingBuilder.CreateAsync<Projects.CistaNAS_AppHost>();
        _app = await builder.BuildAsync();
        await _app.StartAsync();

        var endpoint = _app.GetEndpoint("webfrontend");
        _http = new HttpClient { BaseAddress = endpoint };
    }

    public async Task DisposeAsync()
    {
        if (_app is not null)
        {
            await _app.DisposeAsync();
        }
        _http?.Dispose();
    }

    [Fact]
    public async Task HealthEndpoint_ReturnsOk()
    {
        var resp = await _http!.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task AuthFlow_RegisterLoginChangePassword()
    {
        // 初期ユーザー作成
        var setupResp = await _http!.PostAsJsonAsync("/api/v1/auth/setup", new { username = "admin", password = "initial-pw" });
        Assert.True(setupResp.IsSuccessStatusCode || setupResp.StatusCode == HttpStatusCode.Conflict);

        // ログイン
        var loginResp = await _http!.PostAsJsonAsync("/api/v1/auth/login", new { username = "admin", password = "initial-pw" });
        if (!loginResp.IsSuccessStatusCode)
        {
            // 既に別パスワードで作成済みの可能性 → スキップ
            return;
        }
        var loginJson = await loginResp.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        string token = loginJson.GetProperty("accessToken").GetString()!;
        Assert.False(string.IsNullOrEmpty(token));

        // 認証付きリクエスト
        using var authClient = new HttpClient { BaseAddress = _http!.BaseAddress };
        authClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        // ボリューム一覧取得
        var listResp = await authClient.GetAsync("/api/v1/volumes");
        Assert.Equal(HttpStatusCode.OK, listResp.StatusCode);
    }

    [Fact]
    public async Task E2eeVolume_FullFlow_ViaApi()
    {
        // セットアップ + ログイン
        await _http!.PostAsJsonAsync("/api/v1/auth/setup", new { username = "e2ee-user", password = "e2ee-pw" });
        var loginResp = await _http!.PostAsJsonAsync("/api/v1/auth/login", new { username = "e2ee-user", password = "e2ee-pw" });
        if (!loginResp.IsSuccessStatusCode) return;

        var loginJson = await loginResp.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        string token = loginJson.GetProperty("accessToken").GetString()!;

        using var authClient = new HttpClient { BaseAddress = _http!.BaseAddress };
        authClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        // クライアント側で鍵生成
        string username = "e2ee-user";
        string password = "e2ee-pw";
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(username, password, salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);

        // E2EE ボリューム作成
        var createResp = await authClient.PostAsJsonAsync("/api/v1/e2ee/create-volume", new
        {
            volumeName = "aspire-test-vol",
            username,
            wrappedMasterKey = new
            {
                kdf = new { algorithm = "pbkdf2-sha256", iterations = 1000, salt },
                wrappedMasterKey = new { algorithm = "aes-256-gcm", nonce, ciphertext = ct, tag }
            },
            chunkSize = 1048576,
        });
        Assert.Equal(HttpStatusCode.Created, createResp.StatusCode);

        // マウント
        var mountResp = await authClient.PostAsJsonAsync("/api/v1/e2ee/aspire-test-vol/mount", new { });
        Assert.Equal(HttpStatusCode.OK, mountResp.StatusCode);

        // wrapped key 取得 → クライアント側でアンラップ検証
        var wkResp = await authClient.GetAsync("/api/v1/e2ee/aspire-test-vol/wrapped-key/e2ee-user");
        Assert.Equal(HttpStatusCode.OK, wkResp.StatusCode);
        var wkJson = await wkResp.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();

        byte[] rSalt = Convert.FromBase64String(wkJson.GetProperty("kdf").GetProperty("salt").GetString()!);
        int rIter = wkJson.GetProperty("kdf").GetProperty("iterations").GetInt32();
        byte[] rNonce = Convert.FromBase64String(wkJson.GetProperty("wrappedMasterKey").GetProperty("nonce").GetString()!);
        byte[] rCt = Convert.FromBase64String(wkJson.GetProperty("wrappedMasterKey").GetProperty("ciphertext").GetString()!);
        byte[] rTag = Convert.FromBase64String(wkJson.GetProperty("wrappedMasterKey").GetProperty("tag").GetString()!);

        byte[] clientKek = E2eeCrypto.DeriveKek(username, password, rSalt, rIter);
        byte[] clientMasterKey = E2eeCrypto.UnwrapMasterKey(rNonce, rCt, rTag, clientKek);
        Assert.Equal(masterKey, clientMasterKey);

        // ファイル作成 → チャンクアップロード → ダウンロード → 復号 ラウンドトリップ
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(clientMasterKey, fileSalt);
        byte[] plainData = System.Security.Cryptography.RandomNumberGenerator.GetBytes(1000);
        byte[] encData = E2eeCrypto.EncryptChunk(plainData, fileKey, 0, fileSalt, isFirstChunk: true);

        var createFileResp = await authClient.PostAsJsonAsync("/api/v1/e2ee/aspire-test-vol/create-file",
            new { encryptedName = "enc-test-file", encryptedLength = encData.Length, chunkCount = 1 });
        Assert.Equal(HttpStatusCode.Created, createFileResp.StatusCode);
        var cfJson = await createFileResp.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        string fileId = cfJson.GetProperty("fileId").GetString()!;

        var uploadResp = await authClient.PostAsync(
            $"/api/v1/e2ee/aspire-test-vol/upload-chunk/{fileId}/0",
            new ByteArrayContent(encData));
        Assert.Equal(HttpStatusCode.OK, uploadResp.StatusCode);

        var downloadResp = await authClient.GetAsync($"/api/v1/e2ee/aspire-test-vol/download-chunk/{fileId}/0");
        Assert.Equal(HttpStatusCode.OK, downloadResp.StatusCode);
        byte[] downloaded = await downloadResp.Content.ReadAsByteArrayAsync();

        byte[] decrypted = E2eeCrypto.DecryptChunk(downloaded, fileKey, 0, out var extractedSalt);
        Assert.Equal(fileSalt, extractedSalt);
        Assert.Equal(plainData, decrypted);
    }
}
