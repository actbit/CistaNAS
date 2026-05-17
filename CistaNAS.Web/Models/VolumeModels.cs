namespace CistaNAS.Web.Models;

public sealed record CreateVolumeRequest(string Name, string? Username, string? Password, bool Encrypted = true);
public sealed record MountRequest(string Name, string Username, string? Password);

/// <summary>ボリューム一覧表示用。</summary>
public sealed record VolumeInfo(string Name, bool IsMounted, bool Encrypted, string OwnerUser, DateTimeOffset CreatedAt);

/// <summary>ボリューム操作の業務エラー（誤認証情報・未存在・重複等）。</summary>
public sealed class VolumeException(string message) : Exception(message);
