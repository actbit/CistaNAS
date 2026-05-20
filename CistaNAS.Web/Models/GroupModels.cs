using System.ComponentModel.DataAnnotations;

namespace CistaNAS.Web.Models;

public sealed class GroupAccount
{
    public required string GroupName { get; set; }
    public required string OwnerUser { get; set; }
    public HashSet<string> Members { get; set; } = new(StringComparer.Ordinal);
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed record CreateGroupRequest([Required] [StringLength(64, MinimumLength = 1)] string GroupName);
public sealed record AddGroupMemberRequest([Required] [StringLength(128)] string Username);
public sealed record GrantGroupAccessRequest(
    [Required] [StringLength(64, MinimumLength = 1)] string GroupName,
    [StringLength(256)] string? GranterPassword = null);
