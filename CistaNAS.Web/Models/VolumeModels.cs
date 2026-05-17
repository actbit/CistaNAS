namespace CistaNAS.Web.Models;

public sealed record CreateVolumeRequest(string Name, string? Username, string? Password, bool Encrypted = true);
public sealed record MountRequest(string Name, string Username, string? Password);
public sealed record GrantAccessRequest(string TargetUsername, string TargetPassword, string GranterPassword);
public sealed record RevokeAccessRequest(string TargetUsername);
public sealed record ChangePasswordRequest(string OldPassword, string NewPassword);

/// <summary>ボリューム一覧表示用。</summary>
public sealed record VolumeInfo(
    string Name, bool IsMounted, bool Encrypted, string OwnerUser,
    DateTimeOffset CreatedAt, IReadOnlyList<string> AuthorizedUsers);

/// <summary>ボリューム操作の業務エラー。</summary>
public sealed class VolumeException(string message) : Exception(message);
