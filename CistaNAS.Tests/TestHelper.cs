using CistaNAS.Web.Configuration;
using CistaNAS.Web.Identity;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

/// <summary>
/// テスト用の DI コンテナ構築ヘルパー。
/// SQLite InMemory + Identity + EF Core を使用。
/// </summary>
public static class TestHelper
{
    public static (IServiceProvider sp, string dataRoot) BuildTestServices(
        VolumeOptions? volOpts = null)
    {
        var dataRoot = Path.Combine(Path.GetTempPath(), "cista-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataRoot);
        var opt = new CistaNasOptions
        {
            DataRoot = dataRoot,
            Volume = volOpts ?? new VolumeOptions { SectorSize = 512, KdfIterations = 10_000 },
            Auth = new AuthOptions { Pbkdf2Iterations = 10_000 },
        };
        var io = Options.Create(opt);
        var services = new ServiceCollection();

        // DB: SQLite ファイル（テストごとにユニークパス）
        var dbPath = Path.Combine(dataRoot, "test.db");
        var connStr = $"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared;Pooling=False";
        services.AddDbContext<AppDbContext>(o => o.UseSqlite(connStr));

        // Identity
        services.AddIdentity<ApplicationUser, ApplicationRole>(o =>
        {
            o.Password.RequiredLength = 4;
            o.Password.RequireNonAlphanumeric = false;
            o.Password.RequireUppercase = false;
            o.Password.RequireLowercase = false;
            o.Password.RequireDigit = false;
            o.Lockout.AllowedForNewUsers = false;
            o.Lockout.MaxFailedAccessAttempts = 99;
            o.User.RequireUniqueEmail = false;
        })
        .AddEntityFrameworkStores<AppDbContext>()
        .AddDefaultTokenProviders();

        services.AddScoped<IPasswordHasher<ApplicationUser>, LegacyPasswordHasher>();

        // Storage
        services.AddSingleton<IStorageProvider>(sp =>
        {
            var o = sp.GetRequiredService<IOptions<CistaNasOptions>>().Value;
            return new LocalStorageProvider(o.DataRoot);
        });
        services.AddSingleton(io);

        // Services
        services.AddScoped<AccountService>();
        services.AddScoped<AuthService>();
        services.AddScoped<GroupService>();
        services.AddSingleton<InvitationService>();
        services.AddSingleton(new JwtSigningKey(new byte[32]));
        services.AddSingleton<VolumeMetadataStore>();
        services.AddSingleton<VolumeService>();
        services.AddScoped<JournalService>();
        services.AddScoped<FileService>();
        services.AddScoped<E2eeFileService>();
        services.AddLogging();

        var sp = services.BuildServiceProvider();

        // DB 初期化
        using (var scope = sp.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Database.EnsureCreated();
        }

        return (sp, dataRoot);
    }
}
