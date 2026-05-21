using CistaNAS.Web.Components.Auth;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Configuration;

/// <summary>
/// CistaNAS の Service 層 DI 登録。
/// 規約: ビジネスロジックは Service に集約。状態を持たない Service は Scoped、
/// マウント状態を保持する VolumeService のみ Singleton。
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCistaNasServices(this IServiceCollection services)
    {
        // ストレージプロバイダ
        services.AddSingleton<IStorageProvider>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<CistaNasOptions>>().Value;
            var storage = options.Storage;
            return storage.Provider.ToLowerInvariant() switch
            {
                "local" => new LocalStorageProvider(options.DataRoot),
                "s3" => CreateS3Provider(storage),
                "azureblob" => CreateAzureBlobProvider(storage),
                "gcs" => CreateGcsProvider(storage),
                _ => throw new InvalidOperationException(
                    $"Unknown storage provider: {storage.Provider}. Supported: local, s3, azureblob, gcs")
            };
        });

        // 認証
        services.AddSingleton<UserStore>();
        services.AddScoped<AuthService>();

        // グループ
        services.AddSingleton<GroupStore>();
        services.AddSingleton<InvitationService>();

        // ボリューム
        services.AddSingleton<VolumeMetadataStore>();
        services.AddSingleton<VolumeService>();

        // ファイル・ジャーナル
        services.AddScoped<JournalService>();
        services.AddScoped<FileService>();

        // Blazor 認証状態
        services.AddScoped<AuthenticationStateService>();

        // メディアストリーミング
        services.AddSingleton<StreamingTokenService>();

        return services;
    }

    private static IStorageProvider CreateS3Provider(StorageOptions s)
    {
        var asmName = typeof(LocalStorageProvider).Assembly.FullName;
        var type = Type.GetType($"CistaNAS.Web.Storage.S3StorageProvider, {asmName}", throwOnError: false, ignoreCase: false);
        if (type is null)
            throw new InvalidOperationException(
                "S3 provider requires AWSSDK.S3 NuGet package. Install: dotnet add package AWSSDK.S3");
        return (IStorageProvider)Activator.CreateInstance(type, s.BucketOrContainer, s.RegionOrConnectionString, s.EndpointOverride, s.PathPrefix)!;
    }

    private static IStorageProvider CreateAzureBlobProvider(StorageOptions s)
    {
        var asmName = typeof(LocalStorageProvider).Assembly.FullName;
        var type = Type.GetType($"CistaNAS.Web.Storage.AzureBlobStorageProvider, {asmName}", throwOnError: false, ignoreCase: false);
        if (type is null)
            throw new InvalidOperationException(
                "Azure Blob provider requires Azure.Storage.Blobs NuGet package. Install: dotnet add package Azure.Storage.Blobs");
        return (IStorageProvider)Activator.CreateInstance(type, s.RegionOrConnectionString, s.BucketOrContainer, s.PathPrefix)!;
    }

    private static IStorageProvider CreateGcsProvider(StorageOptions s)
    {
        var asmName = typeof(LocalStorageProvider).Assembly.FullName;
        var type = Type.GetType($"CistaNAS.Web.Storage.GcsStorageProvider, {asmName}", throwOnError: false, ignoreCase: false);
        if (type is null)
            throw new InvalidOperationException(
                "GCS provider requires Google.Cloud.Storage.V1 NuGet package. Install: dotnet add package Google.Cloud.Storage.V1");
        return (IStorageProvider)Activator.CreateInstance(type, s.BucketOrContainer, s.PathPrefix)!;
    }
}
