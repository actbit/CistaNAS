namespace CistaNAS.Web.Models;

public sealed class GroupAccount
{
    public required string GroupName { get; set; }
    public required string OwnerUser { get; set; }
    public HashSet<string> Members { get; set; } = new(StringComparer.Ordinal);
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed record CreateGroupRequest(string GroupName);
public sealed record AddGroupMemberRequest(string Username);
public sealed record GrantGroupAccessRequest(string GroupName, string? GranterPassword = null);
