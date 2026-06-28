using System.Text;
using CistaNAS.Web.Identity;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace CistaNAS.Tests;

/// <summary>
/// DataMigrationService の移行テスト。
/// users.json → DB 移行がトランザクション内で正しく行われることを検証。
/// </summary>
public class DataMigrationTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _vs;

    public DataMigrationTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _vs = _sp.GetRequiredService<VolumeService>();
    }

    [Fact]
    public async Task Migrate_UsersJson_ImportsToDb()
    {
        using var scope = _sp.CreateAsyncScope();
        var storage = scope.ServiceProvider.GetRequiredService<IStorageProvider>();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<DataMigrationTests>>();

        var usersJson = "[{\"username\":\"alice\",\"passwordHash\":\"pbkdf2-sha256$1000$AA==$BB==\",\"role\":\"admin\",\"publicKey\":null}]";
        await storage.WriteAsync("users.json", new MemoryStream(Encoding.UTF8.GetBytes(usersJson)));

        await DataMigrationService.MigrateIfNeededAsync(storage, db, logger);

        Assert.True(await db.Users.AnyAsync(u => u.UserName == "alice"));
        Assert.True(await db.Roles.AnyAsync(r => r.NormalizedName == "ADMIN"));
    }

    /// <summary>旧データの大文字小文字違いロール（"Admin"/"admin"）が衝突せず1ロールに統合されること。</summary>
    [Fact]
    public async Task Migrate_RoleCaseVariants_NoCollision()
    {
        using var scope = _sp.CreateAsyncScope();
        var storage = scope.ServiceProvider.GetRequiredService<IStorageProvider>();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<DataMigrationTests>>();

        var usersJson = "[{\"username\":\"alice\",\"passwordHash\":\"h\",\"role\":\"Admin\"}," +
                        "{\"username\":\"bob\",\"passwordHash\":\"h\",\"role\":\"admin\"}]";
        await storage.WriteAsync("users.json", new MemoryStream(Encoding.UTF8.GetBytes(usersJson)));

        await DataMigrationService.MigrateIfNeededAsync(storage, db, logger);

        // NormalizedName が同じ "ADMIN" に統合され、1ロールのみ
        var adminRoles = await db.Roles.Where(r => r.NormalizedName == "ADMIN").ToListAsync();
        Assert.Single(adminRoles);
        Assert.True(await db.Users.AnyAsync(u => u.UserName == "alice"));
        Assert.True(await db.Users.AnyAsync(u => u.UserName == "bob"));
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var v in await _vs.ListAllAsync())
        {
            try
            {
                var header = await _vs.GetVolumeHeaderAsync(v.Name);
                await _vs.LockAsync(v.Name, header.OwnerUser);
            }
            catch (Exception) { }
        }
        try { if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true); } catch (Exception) { }
    }
}
