using System.Diagnostics;
using CistaNAS.Web.Data;
using CistaNAS.Web.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Xunit;

namespace CistaNAS.Tests;

/// <summary>
/// PostgreSQL コンテナを起動して実マイグレーション適用を検証する Fixture
/// （SQLite 専用になっていないことの実証。CistaNAS.Web.Migrations.PostgreSql を実適用する）。
/// Docker CLI を直接呼び出す（Aspire オーケストレーションに依存しないため単独で動く）。
/// Docker daemon が利用できない環境では Available=false になり、テストは実行時スキップになる。
/// </summary>
public sealed class PostgresContainerFixture : IAsyncLifetime
{
    private string? _containerId;

    public bool Available { get; private set; }
    public string LastError { get; private set; } = "";
    public int Port { get; private set; }

    public async Task InitializeAsync()
    {
        try
        {
            // Docker daemon の稼働確認
            (int code, _) = await RunDockerAsync("info");
            if (code != 0)
            {
                LastError = "docker info に失敗しました（daemon 停止または未インストール）";
                return;
            }

            string name = $"cista-pg-mig-test-{Guid.NewGuid().ToString("N")[..12]}";
            // -P でホスト側の空きポートへ自動割り当て（占用ポートとの衝突を避ける）
            (code, string stdout) = await RunDockerAsync(
                $"run -d --rm --name {name} -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=postgres -P postgres:17-alpine");
            if (code != 0)
            {
                LastError = $"docker run に失敗しました: {stdout}";
                return;
            }
            _containerId = stdout.Trim();

            // 割り当てられたホストポートを取得
            (_, stdout) = await RunDockerAsync($"port {_containerId} 5432/tcp");
            // 出力例: "0.0.0.0:55001\n[::]:55001"
            string? portStr = stdout.Split('\n')
                .Select(l => l.Split(':') is { Length: > 1 } parts ? parts[^1].Trim() : "")
                .FirstOrDefault(p => int.TryParse(p, out _));
            if (portStr is null || !int.TryParse(portStr, out int parsedPort))
            {
                LastError = $"ポート割り当ての解析に失敗しました: {stdout}";
                await CleanupAsync();
                return;
            }
            Port = parsedPort;

            // コンテナ（初回はイメージ pull）の PostgreSQL 起動完了を待つ
            string adminCs = $"Host=localhost;Port={Port};Database=postgres;Username=postgres;Password=postgres";
            var deadline = DateTime.UtcNow.AddMinutes(5);
            while (true)
            {
                try
                {
                    await using var conn = new NpgsqlConnection(adminCs);
                    await conn.OpenAsync();
                    break;
                }
                catch (Exception ex) when (DateTime.UtcNow < deadline)
                {
                    LastError = ex.Message;
                    await Task.Delay(1000);
                }
            }
            Available = true;
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            Available = false;
            await CleanupAsync();
        }
    }

    /// <summary>テスト用の一意データベースを作成して接続文字列を返す。</summary>
    public async Task<string> CreateTestDatabaseAsync()
    {
        string dbName = $"cista_mig_{Guid.NewGuid():N}";
        await using var conn = new NpgsqlConnection(
            $"Host=localhost;Port={Port};Database=postgres;Username=postgres;Password=postgres");
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand($"CREATE DATABASE {dbName}", conn);
        await cmd.ExecuteNonQueryAsync();
        return $"Host=localhost;Port={Port};Database={dbName};Username=postgres;Password=postgres";
    }

    private async Task CleanupAsync()
    {
        if (_containerId is null) return;
        try { await RunDockerAsync($"rm -f {_containerId}"); } catch { }
        _containerId = null;
    }

    public async Task DisposeAsync()
        => await CleanupAsync();

    private static async Task<(int Code, string StdOut)> RunDockerAsync(string args)
    {
        using var psi = new Process
        {
            StartInfo = new ProcessStartInfo("docker", args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            },
        };
        psi.Start();
        string stdout = await psi.StandardOutput.ReadToEndAsync();
        string stderr = await psi.StandardError.ReadToEndAsync();
        await psi.WaitForExitAsync();
        return (psi.ExitCode, stdout + stderr);
    }
}

/// <summary>
/// PostgreSQL migration の実適用テスト（項目 5）。
/// - 全マイグレーションが PostgreSQL に対して実適用されること（SQLite 専用でないこと）
/// - 既存ユーザー（マイグレーション適用前に存在したユーザー）が
///   SharingEnabled=true / EcdhIdentitySalt=null / EcdhDerivationVersion=0 の
///   互換デフォルトを持つこと（既存ユーザーが共有不能・identity 不正にならないこと）
/// - 初期化の冪等性（2 回目の起動で差分適用・エラーがないこと）
/// </summary>
[CollectionDefinition("Postgres")]
public class PostgresTestCollection : ICollectionFixture<PostgresContainerFixture>;

[Collection("Postgres")]
public class PostgreSqlMigrationTests(PostgresContainerFixture pg)
{
    private const string MigrationsAssembly = "CistaNAS.Web.Migrations.PostgreSql";

    private static AppDbContext CreateContext(string connectionString) =>
        new(new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql(connectionString, b => b.MigrationsAssembly(MigrationsAssembly))
            .Options);

    /// <summary>Docker が使えない環境でテストを実行時スキップする（Xunit.SkippableFact）。</summary>
    private void RequireDocker()
        => Skip.IfNot(pg.Available,
            $"Docker daemon が利用できないため PostgreSQL migration テストをスキップしました。{pg.LastError}");

    [SkippableFact]
    public async Task FreshDatabase_AllMigrationsApply_OnPostgreSql()
    {
        RequireDocker();
        string cs = await pg.CreateTestDatabaseAsync();

        using var db = CreateContext(cs);
        var logger = NullLoggerFactory.Instance.CreateLogger("pg-test");
        await DatabaseInitializer.InitializeAsync(db, logger);

        // 全マイグレーションが適用済み
        var applied = await db.Database.GetAppliedMigrationsAsync();
        Assert.Equal(db.Database.GetMigrations().Count(), applied.Count());
        Assert.Contains(applied, m => m.EndsWith("_AddSharingAndEcdhIdentity"));
        Assert.True(await db.Database.CanConnectAsync());

        // 新列が実在する（PostgreSQL の実スキーマ確認）
        await using (var conn = new NpgsqlConnection(cs))
        {
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand(
                "SELECT count(*) FROM information_schema.columns " +
                "WHERE table_name = 'Users' AND column_name IN ('SharingEnabled','EcdhIdentitySalt','EcdhDerivationVersion')", conn);
            Assert.Equal(3L, (long)(await cmd.ExecuteScalarAsync())!);
        }
    }

    [SkippableFact]
    public async Task ExistingUser_GetsCompatibleDefaults_AfterMigration()
    {
        RequireDocker();
        string cs = await pg.CreateTestDatabaseAsync();

        // 1) InitialCreate のみ適用（AddSharingAndEcdhIdentity 以前の DB = 既存環境を再現）
        using (var db = CreateContext(cs))
        {
            string initial = db.Database.GetMigrations().First();
            await db.Database.MigrateAsync(initial);
        }

        // 2) マイグレーション適用前のユーザーを作成（新列はまだ存在しないので生 SQL）
        await using (var conn = new NpgsqlConnection(cs))
        {
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand(
                "INSERT INTO \"Users\" (\"Id\", \"UserName\", \"DefaultEncryptionMode\", \"DefaultCipherAlgorithm\", " +
                "\"EmailConfirmed\", \"PhoneNumberConfirmed\", \"TwoFactorEnabled\", \"LockoutEnabled\", \"AccessFailedCount\") " +
                "VALUES ('legacy-user', 'legacy-user', 'server', 'aes-256-xts', false, false, false, false, 0)", conn);
            await cmd.ExecuteNonQueryAsync();
        }

        // 3) 残りの差分マイグレーションを実適用（起動時と同じ経路）
        using (var db2 = CreateContext(cs))
        {
            var logger = NullLoggerFactory.Instance.CreateLogger("pg-test");
            await DatabaseInitializer.InitializeAsync(db2, logger);

            // 全マイグレーションが揃い、既存データは失われていない
            Assert.Equal(db2.Database.GetMigrations().Count(),
                (await db2.Database.GetAppliedMigrationsAsync()).Count());
        }

        // 4) 既存ユーザーは互換デフォルトを持つ:
        //    SharingEnabled = true（既存ユーザーが共有不能にならない）
        //    EcdhIdentitySalt = null（未セットアップ）
        //    EcdhDerivationVersion = 0（identity 未初期化。次回 identity-setup で現行版に更新される）
        await using (var conn = new NpgsqlConnection(cs))
        {
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand(
                "SELECT \"SharingEnabled\", \"EcdhIdentitySalt\", \"EcdhDerivationVersion\" " +
                "FROM \"Users\" WHERE \"Id\" = 'legacy-user'", conn);
            await using var reader = await cmd.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync(), "既存ユーザーが見つかりません");
            Assert.True(reader.GetBoolean(0), "既存ユーザーの SharingEnabled が true になっていません");
            Assert.True(reader.IsDBNull(1), "既存ユーザーの EcdhIdentitySalt が null になっていません");
            Assert.Equal(0, reader.GetInt32(2));
        }

        // 5) EF 経由でも同じ解釈になること（モデルとの整合）
        using (var db3 = CreateContext(cs))
        {
            var user = await db3.Users.SingleAsync(u => u.UserName == "legacy-user");
            Assert.True(user.SharingEnabled);
            Assert.Null(user.EcdhIdentitySalt);
            Assert.Equal(0, user.EcdhDerivationVersion);

            // モデル既定の通り、新規ユーザーも SharingEnabled=true で作れる（CRUD 可能性の確認）
            db3.Users.Add(new ApplicationUser { UserName = "new-user" });
            await db3.SaveChangesAsync();
        }
    }

    [SkippableFact]
    public async Task Initialize_IsIdempotent_OnPostgreSql()
    {
        RequireDocker();
        string cs = await pg.CreateTestDatabaseAsync();

        using var db = CreateContext(cs);
        var logger = NullLoggerFactory.Instance.CreateLogger("pg-test");
        await DatabaseInitializer.InitializeAsync(db, logger);
        var applied1 = await db.Database.GetAppliedMigrationsAsync();

        using var db2 = CreateContext(cs);
        await DatabaseInitializer.InitializeAsync(db2, logger);
        var applied2 = await db2.Database.GetAppliedMigrationsAsync();

        Assert.Equal(applied1, applied2); // 2 回目で差分適用なし
    }
}
