using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CistaNAS.Web.Identity;

public sealed class AppDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<GroupEntity> Groups { get; set; } = null!;
    public DbSet<GroupMemberEntity> GroupMembers { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<ApplicationUser>(e =>
        {
            e.ToTable("Users");
            e.Property(u => u.PublicKey).HasMaxLength(256);
        });
        builder.Entity<ApplicationRole>(e => e.ToTable("Roles"));
        builder.Entity<IdentityUserRole<string>>(e => e.ToTable("UserRoles"));
        builder.Entity<IdentityRoleClaim<string>>(e => e.ToTable("RoleClaims"));
        builder.Entity<IdentityUserClaim<string>>(e => e.ToTable("UserClaims"));
        builder.Entity<IdentityUserLogin<string>>(e => e.ToTable("UserLogins"));
        builder.Entity<IdentityUserToken<string>>(e => e.ToTable("UserTokens"));

        builder.Entity<GroupEntity>(e =>
        {
            e.ToTable("Groups");
            e.HasKey(g => g.Id);
            e.HasIndex(g => g.GroupName).IsUnique();
            e.Property(g => g.GroupName).HasMaxLength(64).IsRequired();
            e.Property(g => g.OwnerUser).HasMaxLength(128).IsRequired();
            e.HasMany(g => g.Members)
                .WithOne(m => m.Group)
                .HasForeignKey(m => m.GroupId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<GroupMemberEntity>(e =>
        {
            e.ToTable("GroupMembers");
            e.HasKey(m => m.Id);
            e.Property(m => m.Username).HasMaxLength(128).IsRequired();
            e.HasIndex(m => new { m.GroupId, m.Username }).IsUnique();
        });
    }
}

public sealed class GroupEntity
{
    public int Id { get; set; }
    public required string GroupName { get; set; }
    public required string OwnerUser { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public List<GroupMemberEntity> Members { get; set; } = [];
}

public sealed class GroupMemberEntity
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
    public int GroupId { get; set; }
    public GroupEntity Group { get; set; } = null!;
}
