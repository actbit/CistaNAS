using CistaNAS.Web.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace CistaNAS.Web.Migrations.Sqlite;

/// <summary>
/// dotnet ef migrations add 用のデザインタイムファクトリ (このプロジェクトを
/// --project に指定して実行したときに、SQLite プロバイダでマイグレーションを生成する)。
/// </summary>
public sealed class SqliteDesignTimeFactory : IDesignTimeDbContextFactory<AppDbContext>
{
    public AppDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite("Data Source=design-time.db", b => b.MigrationsAssembly("CistaNAS.Web.Migrations.Sqlite"))
            .Options);
}
