using CistaNAS.Web.Identity;
using CistaNAS.Web.Storage;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace CistaNAS.Web.Services;

/// <summary>
/// users.json / groups.json → EF Core DB へのワンタイム移行。
/// 起動時に DB が空かつ旧ファイルが存在する場合に実行。
/// </summary>
public static class DataMigrationService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static async Task MigrateIfNeededAsync(
        IStorageProvider storage,
        AppDbContext db,
        ILogger logger,
        CancellationToken ct = default)
    {
        if (await db.Users.AnyAsync(ct))
        {
            logger.LogInformation("DB にユーザーが存在するため、移行をスキップします。");
            return;
        }

        // users.json の移行
        byte[]? usersData = await storage.ReadAsync("users.json", ct);
        if (usersData is not null)
        {
            try
            {
                var users = JsonSerializer.Deserialize<List<LegacyUserEntry>>(usersData, JsonOptions);
                if (users is not null && users.Count > 0)
                {
                    logger.LogInformation("users.json から {Count} 件のユーザーを移行します...", users.Count);
                    foreach (var entry in users)
                    {
                        db.Users.Add(new ApplicationUser
                        {
                            Id = entry.Username,
                            UserName = entry.Username,
                            NormalizedUserName = entry.Username.ToUpperInvariant(),
                            Email = $"{entry.Username}@cista.local",
                            NormalizedEmail = $"{entry.Username}@cista.local".ToUpperInvariant(),
                            EmailConfirmed = true,
                            SecurityStamp = Guid.NewGuid().ToString(),
                            PasswordHash = entry.PasswordHash,
                            PublicKey = entry.PublicKey,
                        });

                        // Role を IdentityRole テーブルに登録
                        if (!await db.Roles.AnyAsync(r => r.Name == entry.Role, ct))
                        {
                            db.Roles.Add(new ApplicationRole
                            {
                                Id = Guid.NewGuid().ToString(),
                                Name = entry.Role,
                                NormalizedName = entry.Role.ToUpperInvariant(),
                            });
                        }

                        db.UserRoles.Add(new Microsoft.AspNetCore.Identity.IdentityUserRole<string>
                        {
                            UserId = entry.Username,
                            RoleId = (await db.Roles.FirstAsync(r => r.Name == entry.Role, ct)).Id,
                        });
                    }

                    await db.SaveChangesAsync(ct);
                    logger.LogInformation("ユーザー移行完了。");
                }
            }
            catch (JsonException ex)
            {
                logger.LogError(ex, "users.json の解析に失敗しました。移行をスキップします。");
            }
        }

        // groups.json の移行
        byte[]? groupsData = await storage.ReadAsync("groups.json", ct);
        if (groupsData is not null)
        {
            try
            {
                var groups = JsonSerializer.Deserialize<List<LegacyGroupEntry>>(groupsData, JsonOptions);
                if (groups is not null && groups.Count > 0)
                {
                    logger.LogInformation("groups.json から {Count} 件のグループを移行します...", groups.Count);
                    foreach (var entry in groups)
                    {
                        var entity = new GroupEntity
                        {
                            GroupName = entry.GroupName,
                            OwnerUser = entry.OwnerUser,
                            CreatedAt = entry.CreatedAt,
                            Members = entry.Members.Select(m => new GroupMemberEntity { Username = m }).ToList(),
                        };
                        db.Groups.Add(entity);
                    }

                    await db.SaveChangesAsync(ct);
                    logger.LogInformation("グループ移行完了。");
                }
            }
            catch (JsonException ex)
            {
                logger.LogError(ex, "groups.json の解析に失敗しました。移行をスキップします。");
            }
        }
    }

    private sealed class LegacyUserEntry
    {
        public required string Username { get; set; }
        public required string PasswordHash { get; set; }
        public string Role { get; set; } = "user";
        public string? PublicKey { get; set; }
    }

    private sealed class LegacyGroupEntry
    {
        public required string GroupName { get; set; }
        public required string OwnerUser { get; set; }
        public HashSet<string> Members { get; set; } = [];
        public DateTimeOffset CreatedAt { get; set; }
    }
}
