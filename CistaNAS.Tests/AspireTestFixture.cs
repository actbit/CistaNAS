using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// Aspire AppHost を1回だけ起動し、全テストで共有する Fixture。
/// xUnit の ICollectionFixture パターンでシングルトンライフサイクルを保証。
/// </summary>
public class AspireFixture : IAsyncLifetime
{
    private DistributedApplication? _app;
    private string _tempDataRoot = "";

    public HttpClient Http { get; private set; } = null!;
    public CistaNasApiClient Api { get; private set; } = null!;
    public string Token { get; private set; } = "";

    public const string Username = "admin";
    public const string Password = "initial-pw-1234";

    public async Task InitializeAsync()
    {
        // テスト専用の一時ディレクトリを作成
        _tempDataRoot = Path.Combine(Path.GetTempPath(), $"cista-test-{Guid.NewGuid():N}");

        var builder = await DistributedApplicationTestingBuilder.CreateAsync<Projects.CistaNAS_AppHost>();

        // webfrontend の DataRoot を一時ディレクトリに上書き
        var proj = builder.Resources
            .OfType<Aspire.Hosting.ApplicationModel.ProjectResource>()
            .First(r => r.Name == "webfrontend");
        builder.CreateResourceBuilder(proj)
            .WithEnvironment("CistaNas__DataRoot", _tempDataRoot);

        _app = await builder.BuildAsync();
        await _app.StartAsync();

        // HTTPS エンドポイントを取得（HTTP は HTTPS へリダイレクトされ Auth ヘッダーが剥がれる）
        var endpoint = _app.GetEndpoint("webfrontend", "https");
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        Http = new HttpClient(handler) { BaseAddress = endpoint };

        // 初期管理者作成
        var setupResp = await Http.PostAsJsonAsync("/api/v1/auth/setup",
            new { username = Username, password = Password });
        Assert.True(setupResp.IsSuccessStatusCode || setupResp.StatusCode == HttpStatusCode.Conflict);

        // ログイン
        var loginResp = await Http.PostAsJsonAsync("/api/v1/auth/login",
            new { username = Username, password = Password });
        Assert.True(loginResp.IsSuccessStatusCode,
            $"Login failed: {loginResp.StatusCode} - {await loginResp.Content.ReadAsStringAsync()}");

        var loginJson = await loginResp.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Token = loginJson.GetProperty("accessToken").GetString()!;

        // ApiClient にも token を設定
        Api = new CistaNasApiClient(Http);
        Api.SetToken(Token);
    }

    public async Task DisposeAsync()
    {
        Http.Dispose();
        if (_app is not null) await _app.DisposeAsync();

        // テスト用データを一括削除
        if (Directory.Exists(_tempDataRoot))
        {
            try { Directory.Delete(_tempDataRoot, true); }
            catch (IOException) { /* ベストエフォート */ }
        }
    }
}

/// <summary>
/// テストコレクション定義。AspireFixture を1回だけ生成し、
/// コレクション内の全テストクラスで共有する。
/// </summary>
[CollectionDefinition("Aspire")]
public class AspireTestCollection : ICollectionFixture<AspireFixture>;

/// <summary>
/// Aspire 統合テスト: 生 HTTP クライアントによる E2E 検証。
/// </summary>
[Collection("Aspire")]
public class AspireHttpTests(AspireFixture fixture)
{
    private HttpClient Http => fixture.Http;
    private string Token => fixture.Token;

    [Fact]
    public async Task HealthEndpoint_ReturnsOk()
    {
        var resp = await Http.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task AuthFlow_VolumesEndpoint_ReturnsOk()
    {
        using var authClient = new HttpClient { BaseAddress = Http.BaseAddress };
        authClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", Token);
        var listResp = await authClient.GetAsync("/api/v1/volumes");
        Assert.Equal(HttpStatusCode.OK, listResp.StatusCode);
    }

    [Fact]
    public async Task E2eeVolume_FullFlow_ViaHttp()
    {
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(AspireFixture.Username, AspireFixture.Password, salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);

        string volName = $"http-e2ee-{Guid.NewGuid():N}";

        using var authClient = new HttpClient { BaseAddress = Http.BaseAddress };
        authClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", Token);

        var createResp = await authClient.PostAsJsonAsync("/api/v1/e2ee/create-volume", new
        {
            volumeName = volName,
            username = AspireFixture.Username,
            wrappedMasterKey = new
            {
                kdf = new { algorithm = "pbkdf2-sha256", iterations = 1000, salt },
                wrappedMasterKey = new { algorithm = "aes-256-gcm", nonce, ciphertext = ct, tag }
            },
            chunkSize = 1048576,
        });
        Assert.Equal(HttpStatusCode.Created, createResp.StatusCode);

        // wrapped key → アンラップ検証
        var wkResp = await authClient.GetAsync($"/api/v1/e2ee/{volName}/wrapped-key/{AspireFixture.Username}");
        Assert.Equal(HttpStatusCode.OK, wkResp.StatusCode);
        var wkJson = await wkResp.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();

        byte[] rSalt = Convert.FromBase64String(wkJson.GetProperty("kdf").GetProperty("salt").GetString()!);
        int rIter = wkJson.GetProperty("kdf").GetProperty("iterations").GetInt32();
        byte[] rNonce = Convert.FromBase64String(wkJson.GetProperty("wrappedMasterKey").GetProperty("nonce").GetString()!);
        byte[] rCt = Convert.FromBase64String(wkJson.GetProperty("wrappedMasterKey").GetProperty("ciphertext").GetString()!);
        byte[] rTag = Convert.FromBase64String(wkJson.GetProperty("wrappedMasterKey").GetProperty("tag").GetString()!);

        byte[] clientKek = E2eeCrypto.DeriveKek(AspireFixture.Username, AspireFixture.Password, rSalt, rIter);
        byte[] clientMasterKey = E2eeCrypto.UnwrapMasterKey(rNonce, rCt, rTag, clientKek);
        Assert.Equal(masterKey, clientMasterKey);

        // ファイル ラウンドトリップ
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(clientMasterKey, fileSalt);
        byte[] plainData = RandomNumberGenerator.GetBytes(1000);
        byte[] encData = E2eeCrypto.EncryptChunk(plainData, fileKey, 0, fileSalt, isFirstChunk: true);

        var createFileResp = await authClient.PostAsJsonAsync($"/api/v1/e2ee/{volName}/create-file",
            new { encryptedName = "enc-test-file", encryptedLength = encData.Length, chunkCount = 1 });
        Assert.Equal(HttpStatusCode.Created, createFileResp.StatusCode);
        var cfJson = await createFileResp.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        string fileId = cfJson.GetProperty("fileId").GetString()!;

        await authClient.PostAsync($"/api/v1/e2ee/{volName}/upload-chunk/{fileId}/0",
            new ByteArrayContent(encData));

        var downloadResp = await authClient.GetAsync($"/api/v1/e2ee/{volName}/download-chunk/{fileId}/0");
        byte[] downloaded = await downloadResp.Content.ReadAsByteArrayAsync();

        byte[] decrypted = E2eeCrypto.DecryptChunk(downloaded, fileKey, 0, out var extractedSalt);
        Assert.Equal(fileSalt, extractedSalt);
        Assert.Equal(plainData, decrypted);
    }
}

/// <summary>
/// CistaNasApiClient 結合テスト: Typed API クライアントによる E2E 検証。
/// </summary>
[Collection("Aspire")]
public class ApiClientTests(AspireFixture fixture)
{
    private CistaNasApiClient Api => fixture.Api;

    [Fact]
    public async Task ListVolumesAsync_ReturnsList()
    {
        var volumes = await Api.ListVolumesAsync();
        Assert.NotNull(volumes);
    }

    [Fact]
    public async Task E2ee_FullRoundtrip()
    {
        string volName = $"api-full-{Guid.NewGuid():N}";

        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(AspireFixture.Username, AspireFixture.Password, salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        CryptographicOperations.ZeroMemory(kek);

        await Api.CreateVolumeAsync(volName, AspireFixture.Username, nonce, ct, tag, salt, 1000);

        var wkInfo = await Api.GetWrappedKeyAsync(volName, AspireFixture.Username);
        Assert.Equal(1000, wkInfo.KdfIterations);

        byte[] clientKek = E2eeCrypto.DeriveKek(AspireFixture.Username, AspireFixture.Password, wkInfo.KdfSalt, wkInfo.KdfIterations);
        byte[] clientMasterKey = E2eeCrypto.UnwrapMasterKey(
            wkInfo.WrappedNonce, wkInfo.WrappedCiphertext, wkInfo.WrappedTag, clientKek);
        CryptographicOperations.ZeroMemory(clientKek);
        Assert.Equal(masterKey, clientMasterKey);

        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(clientMasterKey, fileSalt);
        byte[] plainData = RandomNumberGenerator.GetBytes(2000);
        byte[] encData = E2eeCrypto.EncryptChunk(plainData, fileKey, 0, fileSalt, isFirstChunk: true);

        string fileId = await Api.CreateFileAsync(volName, "enc-test-file", encData.Length, 1);
        Assert.False(string.IsNullOrEmpty(fileId));

        await Api.UploadChunkAsync(volName, fileId, 0, encData);
        var (downloaded, _) = await Api.DownloadChunkAsync(volName, fileId, 0);

        byte[] decrypted = E2eeCrypto.DecryptChunk(downloaded, fileKey, 0, out var extractedSalt);
        Assert.Equal(fileSalt, extractedSalt);
        Assert.Equal(plainData, decrypted);

        var files = await Api.ListFilesAsync(volName);
        Assert.Single(files);
        Assert.Equal(fileId, files[0].FileId);

        await Api.DeleteFileAsync(volName, fileId);
        Assert.Empty(await Api.ListFilesAsync(volName));

        CryptographicOperations.ZeroMemory(clientMasterKey);
    }

    [Fact]
    public async Task E2ee_FilenameEncryption_Roundtrip()
    {
        string volName = $"api-fname-{Guid.NewGuid():N}";

        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(AspireFixture.Username, AspireFixture.Password, salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        CryptographicOperations.ZeroMemory(kek);

        await Api.CreateVolumeAsync(volName, AspireFixture.Username, nonce, ct, tag, salt, 1000);

        var wkInfo = await Api.GetWrappedKeyAsync(volName, AspireFixture.Username);
        byte[] clientKek = E2eeCrypto.DeriveKek(AspireFixture.Username, AspireFixture.Password, wkInfo.KdfSalt, wkInfo.KdfIterations);
        byte[] clientMasterKey = E2eeCrypto.UnwrapMasterKey(
            wkInfo.WrappedNonce, wkInfo.WrappedCiphertext, wkInfo.WrappedTag, clientKek);
        CryptographicOperations.ZeroMemory(clientKek);

        string plainName = "日本語ファイル名_2025-06-01.txt";
        string encName = E2eeCrypto.EncryptFilename(plainName, clientMasterKey);

        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(clientMasterKey, fileSalt);
        byte[] dummyData = RandomNumberGenerator.GetBytes(100);
        byte[] encData = E2eeCrypto.EncryptChunk(dummyData, fileKey, 0, fileSalt, isFirstChunk: true);

        string fileId = await Api.CreateFileAsync(volName, encName, encData.Length, 1);
        await Api.UploadChunkAsync(volName, fileId, 0, encData);

        var files = await Api.ListFilesAsync(volName);
        Assert.Single(files);

        string decName = E2eeCrypto.DecryptFilename(files[0].EncryptedName, clientMasterKey);
        Assert.Equal(plainName, decName);

        CryptographicOperations.ZeroMemory(clientMasterKey);
    }

    [Fact]
    public async Task E2ee_MultiChunk_UploadDownload()
    {
        string volName = $"api-multi-{Guid.NewGuid():N}";

        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(AspireFixture.Username, AspireFixture.Password, salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        CryptographicOperations.ZeroMemory(kek);

        await Api.CreateVolumeAsync(volName, AspireFixture.Username, nonce, ct, tag, salt, 1000);

        var wkInfo = await Api.GetWrappedKeyAsync(volName, AspireFixture.Username);
        byte[] clientKek = E2eeCrypto.DeriveKek(AspireFixture.Username, AspireFixture.Password, wkInfo.KdfSalt, wkInfo.KdfIterations);
        byte[] clientMasterKey = E2eeCrypto.UnwrapMasterKey(
            wkInfo.WrappedNonce, wkInfo.WrappedCiphertext, wkInfo.WrappedTag, clientKek);
        CryptographicOperations.ZeroMemory(clientKek);

        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(clientMasterKey, fileSalt);

        byte[][] plainChunks =
        [
            RandomNumberGenerator.GetBytes(500),
            RandomNumberGenerator.GetBytes(300),
            RandomNumberGenerator.GetBytes(100),
        ];
        byte[][] encChunks =
        [
            E2eeCrypto.EncryptChunk(plainChunks[0], fileKey, 0, fileSalt, isFirstChunk: true),
            E2eeCrypto.EncryptChunk(plainChunks[1], fileKey, 1, fileSalt, isFirstChunk: false),
            E2eeCrypto.EncryptChunk(plainChunks[2], fileKey, 2, fileSalt, isFirstChunk: false),
        ];

        long totalLen = encChunks.Sum(c => c.Length);
        string fileId = await Api.CreateFileAsync(volName, "multi-chunk-file", totalLen, 3);

        for (int i = 0; i < 3; i++)
            await Api.UploadChunkAsync(volName, fileId, i, encChunks[i]);

        // チャンク0からfileSaltを取得
        var (downloaded0, _) = await Api.DownloadChunkAsync(volName, fileId, 0);
        byte[] decrypted0 = E2eeCrypto.DecryptChunk(downloaded0, fileKey, 0, out var salt0);
        Assert.Equal(plainChunks[0], decrypted0);

        // 残りのチャンクを復号（fileSaltを再利用）
        for (int i = 1; i < 3; i++)
        {
            var (downloaded, _) = await Api.DownloadChunkAsync(volName, fileId, i);
            byte[] decrypted = E2eeCrypto.DecryptChunk(downloaded, fileKey, i, salt0);
            Assert.Equal(plainChunks[i], decrypted);
        }

        CryptographicOperations.ZeroMemory(clientMasterKey);
    }
}
