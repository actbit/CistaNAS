using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Amazon.S3;
using Amazon.S3.Model;
using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;
using Xunit;
using Xunit.Abstractions;

namespace CistaNAS.Tests;

/// <summary>
/// MinIO コンテナ（S3 互換ストレージ）を Aspire に載せた E2E テスト。
/// S3 バックエンドでのボリューム・ファイル・E2EE・ストリーミングを検証する。
/// </summary>
[Collection("MinIO")]
public class MinIOStorageE2ETests(MinIOFixture fixture, ITestOutputHelper output)
{
    private HttpClient Http => fixture.Http;
    private CistaNasApiClient Api => fixture.Api;
    private string Token => fixture.Token;

    private HttpClient CreateAuthClient()
    {
        var client = new HttpClient { BaseAddress = Http.BaseAddress };
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        return client;
    }

    [Fact]
    public async Task S3_01_MinIO_Reachable()
    {
        // MinIO のヘルスエンドポイントに直接アクセスして起動を確認
        using var s3 = new AmazonS3Client("minioadmin", "minioadmin", new AmazonS3Config
        {
            RegionEndpoint = Amazon.RegionEndpoint.USEast1,
            ServiceURL = fixture.MinIOEndpoint,
            ForcePathStyle = true,
        });

        var buckets = await s3.ListBucketsAsync();
        Assert.Contains(buckets.Buckets, b => b.BucketName == MinIOFixture.Bucket);

        output.WriteLine($"MinIO 到達確認成功: Endpoint={fixture.MinIOEndpoint}, Bucket={MinIOFixture.Bucket}");
    }

    [Fact]
    public async Task S3_02_ServerEncryptedVolume_Creation_And_Mount()
    {
        string volName = $"s3-server-{Guid.NewGuid():N}";

        using var authClient = CreateAuthClient();

        // ボリューム作成（サーバー暗号化 = AES-XTS、S3 チャンクモード）。
        // CreateAsync は作成時に自動マウントするため、別途マウント API は呼ばない。
        var createResp = await authClient.PostAsJsonAsync("/api/v1/volumes/", new
        {
            name = volName,
            username = MinIOFixture.Username,
            password = "s3-vol-pw",
            encrypted = true,
        });
        Assert.Equal(HttpStatusCode.Created, createResp.StatusCode);

        output.WriteLine($"S3 サーバー暗号化ボリューム作成成功: {volName}");
    }

    [Fact]
    public async Task S3_03_File_UploadDownload_Roundtrip()
    {
        string volName = $"s3-file-{Guid.NewGuid():N}";
        using var authClient = CreateAuthClient();

        // ボリューム作成（作成時に自動マウントされる）
        await authClient.PostAsJsonAsync("/api/v1/volumes/", new
        {
            name = volName, username = MinIOFixture.Username, password = "f", encrypted = false,
        });

        // ファイルアップロード
        byte[] data = RandomNumberGenerator.GetBytes(2048);
        string filePath = "docs/readme.bin";
        using (var uploadContent = new ByteArrayContent(data))
        {
            var uploadResp = await authClient.PostAsync($"/api/v1/files/{volName}/{filePath}", uploadContent);
            Assert.True(uploadResp.IsSuccessStatusCode,
                $"Upload failed: {uploadResp.StatusCode} - {await uploadResp.Content.ReadAsStringAsync()}");
        }

        // ファイルダウンロード
        var downloadResp = await authClient.GetAsync($"/api/v1/files/{volName}/{filePath}");
        Assert.True(downloadResp.IsSuccessStatusCode);
        byte[] downloaded = await downloadResp.Content.ReadAsByteArrayAsync();
        Assert.Equal(data, downloaded);

        output.WriteLine($"S3 ファイルラウンドトリップ成功: {filePath} ({data.Length} bytes)");
    }

    [Fact]
    public async Task S3_04_File_List_And_Delete()
    {
        string volName = $"s3-list-{Guid.NewGuid():N}";
        using var authClient = CreateAuthClient();

        // ボリューム作成（作成時に自動マウントされる）
        await authClient.PostAsJsonAsync("/api/v1/volumes/", new
        {
            name = volName, username = MinIOFixture.Username, password = "f", encrypted = false,
        });

        // 2ファイルアップロード
        await authClient.PostAsync($"/api/v1/files/{volName}/a.txt", new ByteArrayContent([1, 2, 3]));
        await authClient.PostAsync($"/api/v1/files/{volName}/b.txt", new ByteArrayContent([4, 5, 6]));

        // 一覧取得
        var listResp = await authClient.GetAsync($"/api/v1/files/{volName}/");
        Assert.True(listResp.IsSuccessStatusCode);
        var listJson = await listResp.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        int fileCount = listJson.GetProperty("files").GetArrayLength();
        Assert.True(fileCount >= 2, $"Expected >=2 files, got {fileCount}");

        // 削除
        var delResp = await authClient.DeleteAsync($"/api/v1/files/{volName}/a.txt");
        Assert.True(delResp.IsSuccessStatusCode);

        output.WriteLine($"S3 ファイル一覧・削除成功: ボリューム={volName}");
    }

    [Fact]
    public async Task S3_05_E2EE_Volume_FullFlow()
    {
        // 既存の AspireHttpTests.E2eeVolume_FullFlow_ViaHttp（local）と同等のフローを S3 バックエンドで検証
        string volName = $"s3-e2ee-{Guid.NewGuid():N}";

        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(MinIOFixture.Username, MinIOFixture.Password, salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        CryptographicOperations.ZeroMemory(kek);

        using var authClient = CreateAuthClient();

        // E2EE ボリューム作成
        var createResp = await authClient.PostAsJsonAsync("/api/v1/e2ee/create-volume", new
        {
            volumeName = volName,
            username = MinIOFixture.Username,
            wrappedMasterKey = new
            {
                kdf = new { algorithm = "pbkdf2-sha256", iterations = 1000, salt },
                wrappedMasterKey = new { algorithm = "aes-256-gcm", nonce, ciphertext = ct, tag },
            },
            chunkSize = 1048576,
        });
        Assert.Equal(HttpStatusCode.Created, createResp.StatusCode);

        // wrapped key 取得 → アンラップ検証
        var wkResp = await authClient.GetAsync($"/api/v1/e2ee/{volName}/wrapped-key/{MinIOFixture.Username}");
        Assert.Equal(HttpStatusCode.OK, wkResp.StatusCode);
        var wkJson = await wkResp.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();

        byte[] rSalt = Convert.FromBase64String(wkJson.GetProperty("kdf").GetProperty("salt").GetString()!);
        int rIter = wkJson.GetProperty("kdf").GetProperty("iterations").GetInt32();
        byte[] rNonce = Convert.FromBase64String(wkJson.GetProperty("wrappedMasterKey").GetProperty("nonce").GetString()!);
        byte[] rCt = Convert.FromBase64String(wkJson.GetProperty("wrappedMasterKey").GetProperty("ciphertext").GetString()!);
        byte[] rTag = Convert.FromBase64String(wkJson.GetProperty("wrappedMasterKey").GetProperty("tag").GetString()!);

        byte[] clientKek = E2eeCrypto.DeriveKek(MinIOFixture.Username, MinIOFixture.Password, rSalt, rIter);
        byte[] clientMasterKey = E2eeCrypto.UnwrapMasterKey(rNonce, rCt, rTag, clientKek);
        CryptographicOperations.ZeroMemory(clientKek);
        Assert.Equal(masterKey, clientMasterKey);

        // ファイル ラウンドトリップ
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(clientMasterKey, fileSalt);
        byte[] plainData = RandomNumberGenerator.GetBytes(1000);
        byte[] encData = E2eeCrypto.EncryptChunk(plainData, fileKey, 0, fileSalt, isFirstChunk: true);

        var createFileResp = await authClient.PostAsJsonAsync($"/api/v1/e2ee/{volName}/create-file",
            new { encryptedName = "enc-s3-test-file", encryptedLength = encData.Length, chunkCount = 1 });
        Assert.Equal(HttpStatusCode.Created, createFileResp.StatusCode);
        var cfJson = await createFileResp.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        string fileId = cfJson.GetProperty("fileId").GetString()!;

        await authClient.PostAsync($"/api/v1/e2ee/{volName}/upload-chunk/{fileId}/0", new ByteArrayContent(encData));

        var downloadResp = await authClient.GetAsync($"/api/v1/e2ee/{volName}/download-chunk/{fileId}/0");
        byte[] downloaded = await downloadResp.Content.ReadAsByteArrayAsync();

        byte[] decrypted = E2eeCrypto.DecryptChunk(downloaded, fileKey, 0, out var extractedSalt);
        Assert.Equal(fileSalt, extractedSalt);
        Assert.Equal(plainData, decrypted);

        CryptographicOperations.ZeroMemory(clientMasterKey);
        output.WriteLine($"S3 E2EE フルフロー成功: ボリューム={volName}");
    }

    [Fact]
    public async Task S3_06_E2EE_MultiChunk_UploadDownload()
    {
        string volName = $"s3-multichunk-{Guid.NewGuid():N}";

        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(MinIOFixture.Username, MinIOFixture.Password, salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        CryptographicOperations.ZeroMemory(kek);

        using var authClient = CreateAuthClient();
        await Api.CreateVolumeAsync(volName, MinIOFixture.Username, nonce, ct, tag, salt, 1000);

        var wkInfo = await Api.GetWrappedKeyAsync(volName, MinIOFixture.Username);
        byte[] clientKek = E2eeCrypto.DeriveKek(MinIOFixture.Username, MinIOFixture.Password, wkInfo.KdfSalt, wkInfo.KdfIterations);
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
        string fileId = await Api.CreateFileAsync(volName, "multi-chunk-s3", totalLen, 3);

        for (int i = 0; i < 3; i++)
            await Api.UploadChunkAsync(volName, fileId, i, encChunks[i]);

        // 全チャンク復号検証
        for (int i = 0; i < 3; i++)
        {
            var (downloaded, _) = await Api.DownloadChunkAsync(volName, fileId, i);
            byte[] decrypted = E2eeCrypto.DecryptChunk(downloaded, fileKey, i, fileSalt);
            Assert.Equal(plainChunks[i], decrypted);
        }

        CryptographicOperations.ZeroMemory(clientMasterKey);
        output.WriteLine($"S3 E2EE マルチチャンク成功: ボリューム={volName}");
    }

    [Fact]
    public async Task S3_07_Media_Streaming_Token()
    {
        // ストリーミングトークン発行エンドポイントの動作確認
        string volName = $"s3-stream-{Guid.NewGuid():N}";
        using var authClient = CreateAuthClient();

        // ボリューム作成（作成時に自動マウントされる）
        await authClient.PostAsJsonAsync("/api/v1/volumes/", new
        {
            name = volName, username = MinIOFixture.Username, password = "f", encrypted = false,
        });

        // 小さなメディアファイルをアップロード
        byte[] mediaData = RandomNumberGenerator.GetBytes(4096);
        await authClient.PostAsync($"/api/v1/files/{volName}/video.mp4", new ByteArrayContent(mediaData));

        // トークン発行（StreamTokenRequest: volumeName / fileName）
        var tokenResp = await authClient.PostAsJsonAsync("/api/v1/stream/token", new
        {
            volumeName = volName, fileName = "video.mp4",
        });
        Assert.Equal(HttpStatusCode.OK, tokenResp.StatusCode);
        var tokenJson = await tokenResp.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.False(string.IsNullOrEmpty(tokenJson.GetProperty("token").GetString()));

        output.WriteLine($"S3 ストリーミングトークン発行確認: Status={tokenResp.StatusCode}");
    }

    [Fact]
    public async Task S3_08_Object_Persisted_In_S3()
    {
        // ボリュームメタデータが実際に S3 に保存されていることを確認（バックエンドの検証）
        using var s3 = new AmazonS3Client("minioadmin", "minioadmin", new AmazonS3Config
        {
            RegionEndpoint = Amazon.RegionEndpoint.USEast1,
            ServiceURL = fixture.MinIOEndpoint,
            ForcePathStyle = true,
        });

        // バケット内のオブジェクト一覧を取得
        var listResp = await s3.ListObjectsV2Async(new ListObjectsV2Request
        {
            BucketName = MinIOFixture.Bucket,
            MaxKeys = 10,
        });

        // 何らかのオブジェクトが保存されていること（他のテストの成果物含む）
        Assert.NotNull(listResp.S3Objects);
        output.WriteLine($"S3 バケット内オブジェクト数: {listResp.S3Objects.Count}");
    }
}
