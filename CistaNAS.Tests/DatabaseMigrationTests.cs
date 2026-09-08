using CistaNAS.Web.Data;
using CistaNAS.Web.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace CistaNAS.Tests;

/// <summary>
/// DatabaseInitializer (起動時 EF マイグレーション適用) のテスト。
/// 新規 DB / EnsureCreated 由来のレガシー DB / 冪等性を検証する (SQLite)。
/// </summary>
public class DatabaseMigrationTests
{
    private const string MigrationsAssembly = "CistaNAS.Web.Migrations.Sqlite";

    private static string NewDbPath() =>
        Path.Combine(Path.GetTempPath(), $"cista-mig-{Guid.NewGuid():N}.db");

    private static AppDbContext CreateContext(string dbPath) =>
        new(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite($"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared",
                b => b.MigrationsAssembly(MigrationsAssembly))
            .Options);

    private static async Task<List<string>> GetAppliedAsync(AppDbContext db) =>
        [.. await db.Database.GetAppliedMigrationsAsync()];

    [Fact]
    public async Task FreshDatabase_AppliesInitialCreate_AndIsIdempotent()
    {
        string dbPath = NewDbPath();
        try
        {
            using (var db = CreateContext(dbPath))
            {
                var logger = NullLoggerFactory.Instance.CreateLogger("test");
                await DatabaseInitializer.InitializeAsync(db, logger);

                // テーブルが作成されている
                Assert.True(await db.Database.CanConnectAsync());
                var applied = await GetAppliedAsync(db);
                var migration = Assert.Single(applied);
                Assert.EndsWith("_InitialCreate", migration);

                // 実際に CRUD できる
                db.Users.Add(new ApplicationUser { UserName = "alice" });
                await db.SaveChangesAsync();
            }

            // 2 回目の起動で差分適用なし・エラーなし (冪等)
            using (var db2 = CreateContext(dbPath))
            {
                var logger = NullLoggerFactory.Instance.CreateLogger("test");
                await DatabaseInitializer.InitializeAsync(db2, logger);
                Assert.Single(await GetAppliedAsync(db2));
                Assert.Equal("alice", (await db2.Users.SingleAsync()).UserName);
            }
        }
        finally
        {
            SqliteConnection.ClearAllPools(); // 接続プールがファイルを掴んでいるため削除前に解放
            if (File.Exists(dbPath)) File.Delete(dbPath);
        }
    }

    [Fact]
    public async Task LegacyEnsureCreatedDatabase_IsBaselined_AndDataSurvives()
    {
        string dbPath = NewDbPath();
        try
        {
            // EF Migrations 導入前の DB をシミュレート: EnsureCreated で作成しデータ投入
            using (var db = CreateContext(dbPath))
            {
                await db.Database.EnsureCreatedAsync();
                Assert.Empty(await GetAppliedAsync(db)); // 履歴テーブルは存在しない
                db.Users.Add(new ApplicationUser { UserName = "legacy-user" });
                db.Groups.Add(new GroupEntity { GroupName = "g1", OwnerUser = "legacy-user" });
                await db.SaveChangesAsync();
            }

            using (var db2 = CreateContext(dbPath))
            {
                var logger = NullLoggerFactory.Instance.CreateLogger("test");
                await DatabaseInitializer.InitializeAsync(db2, logger);

                // InitialCreate が適用済みとして記録され、以後のマイグレーション差分が効く状態になる
                var migration = Assert.Single(await GetAppliedAsync(db2));
                Assert.EndsWith("_InitialCreate", migration);

                // 既存データは失われない
                Assert.Equal("legacy-user", (await db2.Users.SingleAsync()).UserName);
                Assert.Equal("g1", (await db2.Groups.SingleAsync()).GroupName);
            }

            // ベースライン後も冪等
            using (var db3 = CreateContext(dbPath))
            {
                var logger = NullLoggerFactory.Instance.CreateLogger("test");
                await DatabaseInitializer.InitializeAsync(db3, logger);
                Assert.Single(await GetAppliedAsync(db3));
            }
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(dbPath)) File.Delete(dbPath);
        }
    }
}
