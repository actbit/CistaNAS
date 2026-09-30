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
            List<string> applied;
            using (var db = CreateContext(dbPath))
            {
                var logger = NullLoggerFactory.Instance.CreateLogger("test");
                await DatabaseInitializer.InitializeAsync(db, logger);

                // テーブルが作成されている
                Assert.True(await db.Database.CanConnectAsync());
                applied = await GetAppliedAsync(db);
                Assert.True(applied.Count >= 1);
                Assert.EndsWith("_InitialCreate", applied[0]);

                // 実際に CRUD できる
                db.Users.Add(new ApplicationUser { UserName = "alice" });
                await db.SaveChangesAsync();
            }

            // 2 回目の起動で差分適用なし・エラーなし (冪等)
            using (var db2 = CreateContext(dbPath))
            {
                var logger = NullLoggerFactory.Instance.CreateLogger("test");
                await DatabaseInitializer.InitializeAsync(db2, logger);
                Assert.Equal(applied, await GetAppliedAsync(db2));
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
            // EF Migrations 導入前の DB をシミュレートする。
            // InitialCreate まで適用した後、履歴テーブルを削除すれば「InitialCreate 時点の
            // スキーマ + 履歴なし」= EnsureCreated 時代のレガシー DB と同じ状態になる。
            // （現行モデルの EnsureCreated は最新スキーマを作ってしまうため使わない）
            using (var db = CreateContext(dbPath))
            {
                string initial = db.Database.GetMigrations().First();
                await db.Database.MigrateAsync(initial);
                await db.Database.ExecuteSqlRawAsync("DROP TABLE __EFMigrationsHistory");
                Assert.Empty(await GetAppliedAsync(db)); // 履歴テーブルは存在しない
                // レガシースキーマ (InitialCreate 時点) には現行モデルの新列がないため
                // EF 経由の SaveChanges は不可。生 SQL でデータ投入する。
                await db.Database.ExecuteSqlRawAsync(
                    "INSERT INTO Users (Id, UserName, DefaultEncryptionMode, DefaultCipherAlgorithm, " +
                    "EmailConfirmed, PhoneNumberConfirmed, TwoFactorEnabled, LockoutEnabled, AccessFailedCount) " +
                    "VALUES ('legacy-user', 'legacy-user', 'server', 'aes-gcm', 0, 0, 0, 0, 0)");
                await db.Database.ExecuteSqlRawAsync(
                    "INSERT INTO Groups (GroupName, OwnerUser, CreatedAt) " +
                    "VALUES ('g1', 'legacy-user', '2026-01-01 00:00:00+00:00')");
            }

            using (var db2 = CreateContext(dbPath))
            {
                var logger = NullLoggerFactory.Instance.CreateLogger("test");
                await DatabaseInitializer.InitializeAsync(db2, logger);

                // InitialCreate が適用済みとして記録され、以後のマイグレーション差分が効く状態になる
                var applied = await GetAppliedAsync(db2);
                Assert.True(applied.Count >= 1);
                Assert.EndsWith("_InitialCreate", applied[0]);

                // 既存データは失われない
                Assert.Equal("legacy-user", (await db2.Users.SingleAsync()).UserName);
                Assert.Equal("g1", (await db2.Groups.SingleAsync()).GroupName);
            }

            // ベースライン後も冪等
            using (var db3 = CreateContext(dbPath))
            {
                var logger = NullLoggerFactory.Instance.CreateLogger("test");
                await DatabaseInitializer.InitializeAsync(db3, logger);
                // 全マイグレーションが適用済みで、追加適用は発生しない
                Assert.Equal(db3.Database.GetMigrations().Count(), (await GetAppliedAsync(db3)).Count);
            }
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(dbPath)) File.Delete(dbPath);
        }
    }
}
