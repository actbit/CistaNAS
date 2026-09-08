using CistaNAS.Web.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace CistaNAS.Web.Migrations.PostgreSql;

/// <summary>
/// dotnet ef migrations add 用のデザインタイムファクトリ (このプロジェクトを
/// --project に指定して実行したときに、PostgreSQL プロバイダでマイグレーションを生成する)。
/// </summary>
public sealed class PostgreSqlDesignTimeFactory : IDesignTimeDbContextFactory<AppDbContext>
{
    public AppDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<AppDbContext>()
            .UseNpgsql("Host=localhost;Database=cistanas-design-time;Username=postgres;Password=postgres",
                b => b.MigrationsAssembly("CistaNAS.Web.Migrations.PostgreSql"))
            .Options);
}
