using System.Net;
using System.Net.Http.Json;
using Amazon.S3;
using Amazon.S3.Model;
using Aspire.Hosting.ApplicationModel;
using CistaNAS.Client.Api;

namespace CistaNAS.Tests;

/// <summary>
/// MinIO コンテナを Aspire に載せて起動するテスト Fixture。
/// AppHost の ENABLE_MINIO 設定で MinIO を起動し、S3 バックエンドで検証する。
/// AspireTestFixture.cs の local ストレージ版を S3 版に差し替えた構成。
/// </summary>
public class MinIOFixture : IAsyncLifetime
{
    private DistributedApplication? _app;
    private string _tempDataRoot = "";

    public HttpClient Http { get; private set; } = null!;
    public CistaNasApiClient Api { get; private set; } = null!;
    public string Token { get; private set; } = "";
    public string MinIOEndpoint { get; private set; } = "";

    public const string Username = "admin";
    public const string Password = "initial-pw-1234";
    public const string Bucket = "cista-e2e-test";

    public async Task InitializeAsync()
    {
        // テスト専用の一時ディレクトリを作成
        _tempDataRoot = Path.Combine(Path.GetTempPath(), $"cista-minio-{Guid.NewGuid():N}");

        // ENABLE_MINIO=true を渡して AppHost を起動 → AppHost 側で MinIO コンテナが立ち上がる
        var builder = await DistributedApplicationTestingBuilder
            .CreateAsync<Projects.CistaNAS_AppHost>(args: ["--ENABLE_MINIO", "true"]);

        // webfrontend の DataRoot とバケット名をテスト用に上書き
        var proj = builder.Resources
            .OfType<ProjectResource>()
            .First(r => r.Name == "webfrontend");
        builder.CreateResourceBuilder(proj)
            .WithEnvironment("CistaNas__DataRoot", _tempDataRoot)
            .WithEnvironment("CistaNas__Storage__BucketOrContainer", Bucket);

        _app = await builder.BuildAsync();
        await _app.StartAsync();

        // MinIO の動的エンドポイントを取得してバケット作成
        MinIOEndpoint = _app.GetEndpoint("minio", "s3").ToString();
        await EnsureBucketAsync(MinIOEndpoint);

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

    /// <summary>MinIO にテスト用バケットを作成（既存なら何もしない）。</summary>
    private static async Task EnsureBucketAsync(string endpoint)
    {
        var config = new AmazonS3Config
        {
            RegionEndpoint = Amazon.RegionEndpoint.USEast1,
            ServiceURL = endpoint,
            ForcePathStyle = true,
        };
        using var s3 = new AmazonS3Client("minioadmin", "minioadmin", config);
        try
        {
            await s3.PutBucketAsync(Bucket);
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == HttpStatusCode.Conflict
                                         || ex.ErrorCode == "BucketAlreadyOwnedByYou")
        {
            // 既に存在する場合は無視
        }
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
/// MinIO テストコレクション定義。MinIOFixture を1回だけ生成し、
/// コレクション内の全テストクラスで共有する。
/// </summary>
[CollectionDefinition("MinIO")]
public class MinIOTestCollection : ICollectionFixture<MinIOFixture>;
