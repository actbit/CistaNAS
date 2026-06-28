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
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        // 旧 users.json/groups.json のキー casing（camelCase/Pascal）に依存しない
        PropertyNameCaseInsensitive = true,
    };

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

        byte[]? usersData = await storage.ReadAsync("users.json", ct);
        byte[]? groupsData = await storage.ReadAsync("groups.json", ct);
        if (usersData is null && groupsData is null) return;

        // users + groups を単一トランザクションで移行する（部分コミットによるアカウント/グループの
        // サイレント消失を防ぐ）。失敗時はロールバックして例外再送し、起動を停止して運用者に通知する。
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        try
        {
            // users.json の移行
            if (usersData is not null)
            {
                var users = JsonSerializer.Deserialize<List<LegacyUserEntry>>(usersData, JsonOptions);
                if (users is not null && users.Count > 0)
                {
                    logger.LogInformation("users.json から {Count} 件のユーザーを移行します...", users.Count);

                    // ロールを正規化名（大文字）で重複排除して一括追加。旧データの大文字小文字違い
                    // （"Admin"/"admin"）で NormalizedName が衝突しないよう、正規化キーを使用する。
                    var roleMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var entry in users)
                    {
                        string normalizedRole = entry.Role.ToUpperInvariant();
                        if (!roleMap.TryGetValue(normalizedRole, out var roleId))
                        {
                            roleId = Guid.NewGuid().ToString();
                            db.Roles.Add(new ApplicationRole
                            {
                                Id = roleId,
                                Name = entry.Role,
                                NormalizedName = normalizedRole,
                            });
                            roleMap[normalizedRole] = roleId;
                        }

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

                        db.UserRoles.Add(new Microsoft.AspNetCore.Identity.IdentityUserRole<string>
                        {
                            UserId = entry.Username,
                            RoleId = roleId,
                        });
                    }

                    await db.SaveChangesAsync(ct);
                    logger.LogInformation("ユーザー移行完了。");
                }
            }

            // groups.json の移行
            if (groupsData is not null)
            {
                var groups = JsonSerializer.Deserialize<List<LegacyGroupEntry>>(groupsData, JsonOptions);
                if (groups is not null && groups.Count > 0)
                {
                    logger.LogInformation("groups.json から {Count} 件のグループを移行します...", groups.Count);
                    foreach (var entry in groups)
                    {
                        db.Groups.Add(new GroupEntity
                        {
                            GroupName = entry.GroupName,
                            OwnerUser = entry.OwnerUser,
                            CreatedAt = entry.CreatedAt,
                            Members = entry.Members.Select(m => new GroupMemberEntity { Username = m }).ToList(),
                        });
                    }

                    await db.SaveChangesAsync(ct);
                    logger.LogInformation("グループ移行完了。");
                }
            }

            await tx.CommitAsync(ct);
        }
        catch (Exception ex)
        {
            await tx.RollbackAsync(ct);
            logger.LogError(ex, "users.json/groups.json の移行に失敗しました。ロールバックしました。");
            throw;
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
