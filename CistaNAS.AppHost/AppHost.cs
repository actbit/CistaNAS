var builder = DistributedApplication.CreateBuilder(args);

// CistaNAS は単一プロセス構成。Service 層 / Blazor / /api/v1 はすべて Web に集約し、
// VolumeService(Singleton) のマウント状態を Blazor と REST で共有する。
builder.AddProject<Projects.CistaNAS_Web>("webfrontend")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health");

builder.Build().Run();
