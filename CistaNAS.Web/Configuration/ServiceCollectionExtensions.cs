using CistaNAS.Web.Components.Auth;
using CistaNAS.Web.Identity;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace CistaNAS.Web.Configuration;

/// <summary>
/// CistaNAS の Service 層 DI 登録。
/// 規約: ビジネスロジックは Service に集約。状態を持たない Service は Scoped、
/// マウント状態を保持する VolumeService のみ Singleton。
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCistaNasServices(this IServiceCollection services, CistaNasOptions cista)
    {
        // ストレージプロバイダ（直接インスタンス化。DI ラムダ外で生成するため ServiceProvider 構築不要）
        var storage = CreateStorageProvider(cista);
        services.AddSingleton<IStorageProvider>(storage);

        // DB プロバイダ + ASP.NET Core Identity + EF Core
        RegisterDatabaseAndIdentity(services, cista, storage);

        // 認証
        services.AddScoped<AccountService>();
        services.AddScoped<AuthService>();

        // グループ
        services.AddScoped<GroupService>();
        // BackgroundService は Singleton 登録でホストが自動起動
        services.AddSingleton<InvitationService>();

        // ボリューム
        services.AddSingleton<VolumeMetadataStore>();
        services.AddSingleton<VolumeService>();

        // ファイル・ジャーナル
        services.AddScoped<JournalService>();
        services.AddScoped<FileService>();
        services.AddScoped<E2eeFileService>();

        // Blazor 認証状態
        services.AddScoped<AuthenticationStateService>();

        // メディアストリーミング（BackgroundService）
        services.AddSingleton<StreamingTokenService>();

        return services;
    }

    private static void RegisterDatabaseAndIdentity(
        IServiceCollection services, CistaNasOptions cista, IStorageProvider storage)
    {
        var db = cista.Database;
        string provider = db.Provider.ToLowerInvariant();

        switch (provider)
        {
            case "postgresql":
                services.AddDbContext<AppDbContext>(o =>
                    o.UseNpgsql(db.ConnectionString));
                break;

            case "s3":
            case "azureblob":
            case "gcs":
            {
                var sync = new CloudSqliteSync(storage, cista.Storage, db);
                services.AddSingleton(sync);
                services.AddDbContext<AppDbContext>(o =>
                o.UseSqlite($"Data Source={sync.LocalDbPath};Mode=ReadWriteCreate;Cache=Shared"));
                break;
            }

            default: // sqlite
            {
                var localPath = db.ConnectionString
                    ?? Path.Combine(cista.DataRoot, "cista.db");
                services.AddDbContext<AppDbContext>(o =>
                o.UseSqlite($"Data Source={localPath};Mode=ReadWriteCreate;Cache=Shared"));
                break;
            }
        }

        services.AddIdentityCore<ApplicationUser>(o =>
        {
            o.Password.RequiredLength = 12;
            o.Password.RequireNonAlphanumeric = false;
            o.Password.RequireUppercase = false;
            o.Password.RequireLowercase = true;
            o.Password.RequireDigit = true;
            o.Lockout.AllowedForNewUsers = true;
            o.Lockout.MaxFailedAccessAttempts = 5;
            o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
            o.User.RequireUniqueEmail = false;
        })
        .AddRoles<ApplicationRole>()
        .AddEntityFrameworkStores<AppDbContext>()
        .AddDefaultTokenProviders();

        // Identity V3 PBKDF2 の反復回数を CistaNasOptions と一致させる
        // （BasicAuthHandler の DummyHash タイミング均一化用）
        services.Configure<PasswordHasherOptions>(o => o.IterationCount = cista.Auth.Pbkdf2Iterations);

        services.AddScoped<IPasswordHasher<ApplicationUser>, LegacyPasswordHasher>();
    }

    private static IStorageProvider CreateStorageProvider(CistaNasOptions cista)
    {
        var storage = cista.Storage;
        return storage.Provider.ToLowerInvariant() switch
        {
            "local" => new LocalStorageProvider(cista.DataRoot),
            "s3" => CreateS3Provider(storage),
            "azureblob" => CreateAzureBlobProvider(storage),
            "gcs" => CreateGcsProvider(storage),
            _ => throw new InvalidOperationException(
                $"Unknown storage provider: {storage.Provider}. Supported: local, s3, azureblob, gcs")
        };
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
