var builder = DistributedApplication.CreateBuilder(args);

// CistaNAS は単一プロセス構成。Service 層 / Blazor / /api/v1 はすべて Web に集約し、
// VolumeService(Singleton) のマウント状態を Blazor と REST で共有する。
var web = builder.AddProject<Projects.CistaNAS_Web>("webfrontend")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health");

// MinIO（S3 互換ストレージ）は環境変数 ENABLE_MINIO=true 時のみ起動。
// デフォルトは local ストレージで本番影響なし。テストやローカル S3 検証で有効化。
if (string.Equals(builder.Configuration["ENABLE_MINIO"], "true", StringComparison.OrdinalIgnoreCase))
{
    var minio = builder.AddContainer("minio", "minio/minio:latest")
        .WithHttpEndpoint(targetPort: 9000, name: "s3")
        .WithHttpEndpoint(targetPort: 9001, name: "console")
        .WithEnvironment("MINIO_ROOT_USER", "minioadmin")
        .WithEnvironment("MINIO_ROOT_PASSWORD", "minioadmin")
        .WithVolume("minio-data", "/data")
        .WithArgs("server", "/data", "--console-address", ":9001");

    // MinIO 有効時は webfrontend を S3 バックエンドに自動切替。
    // EndpointReference を渡すことで services__minio__0__s3 等の環境変数を注入。
    var s3Endpoint = minio.GetEndpoint("s3");
    web.WithEnvironment("CistaNas__Storage__Provider", "s3")
       .WithEnvironment(context =>
       {
           // S3StorageProvider が期待する EndpointOverride を MinIO の動的エンドポイントで上書き
           context.EnvironmentVariables["CistaNas__Storage__EndpointOverride"] = s3Endpoint.Url;
       })
       .WaitFor(minio);
}

builder.Build().Run();
