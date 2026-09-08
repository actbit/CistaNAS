using System.Data;
using CistaNAS.Web.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Logging;

namespace CistaNAS.Web.Data;

/// <summary>
/// 起動時の DB スキーマ初期化。EF Core マイグレーションを構成プロバイダ
/// (SQLite / PostgreSQL) に応じて自動適用する。
/// </summary>
public static class DatabaseInitializer
{
    /// <summary>履歴テーブルに記録する EF 製品バージョン。</summary>
    private static readonly string ProductVersion =
        typeof(IHistoryRepository).Assembly.GetName().Version!.ToString();

    /// <summary>
    /// マイグレーションを適用してスキーマを最新化する。
    /// EF Migrations 導入以前に <c>EnsureCreated</c> で作られた既存 DB
    /// (アプリケーションテーブルはあるが履歴テーブルがない) は、現在のモデルの
    /// InitialCreate を「適用済み」として記録してから差分マイグレーションを適用する。
    /// 新規 DB はそのまま全マイグレーションを適用する。冪等。
    /// </summary>
    public static async Task InitializeAsync(AppDbContext db, ILogger logger, CancellationToken ct = default)
    {
        string providerName = db.Database.ProviderName
            ?? throw new InvalidOperationException("データベース プロバイダーが構成されていません。");
        if (providerName is not ("Microsoft.EntityFrameworkCore.Sqlite" or "Microsoft.EntityFrameworkCore.Npgsql"))
            throw new InvalidOperationException(
                $"未対応のデータベース プロバイダー: {providerName}. 対応: sqlite, postgresql");

        // レガシー EnsureCreated 由来の DB をベースライン登録
        var history = db.GetService<IHistoryRepository>();
        if (!await history.ExistsAsync(ct) && await HasApplicationTableAsync(db, providerName, ct))
        {
            logger.LogInformation(
                "EF Migrations 導入前に作成された既存 DB を検出。InitialCreate を適用済みとして記録します。");
            await history.CreateAsync(ct);
            string initial = db.Database.GetMigrations().FirstOrDefault()
                ?? throw new InvalidOperationException(
                    "マイグレーション アセンブリに InitialCreate が見つかりません。");
            await db.Database.ExecuteSqlRawAsync(
                history.GetInsertScript(new HistoryRow(initial, ProductVersion)), ct);
        }

        await db.Database.MigrateAsync(ct);
    }

    /// <summary>アプリケーション テーブル (Identity の Users) が既に存在するか。</summary>
    private static async Task<bool> HasApplicationTableAsync(
        AppDbContext db, string providerName, CancellationToken ct)
    {
        string sql = providerName switch
        {
            "Microsoft.EntityFrameworkCore.Sqlite" =>
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'Users'",
            "Microsoft.EntityFrameworkCore.Npgsql" =>
                "SELECT COUNT(*) FROM information_schema.tables " +
                "WHERE table_schema = current_schema() AND table_name = 'Users'",
            _ => throw new InvalidOperationException($"未対応のデータベース プロバイダー: {providerName}"),
        };

        var conn = db.Database.GetDbConnection();
        bool wasClosed = conn.State != ConnectionState.Open;
        if (wasClosed) await conn.OpenAsync(ct);
        try
        {
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            var result = await cmd.ExecuteScalarAsync(ct);
            return Convert.ToInt64(result) > 0;
        }
        finally
        {
            if (wasClosed) await conn.CloseAsync();
        }
    }
}
