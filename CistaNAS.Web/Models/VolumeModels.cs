using System.ComponentModel.DataAnnotations;

namespace CistaNAS.Web.Models;

public sealed record CreateVolumeRequest(
    [Required] [StringLength(64, MinimumLength = 1)] string Name,
    [StringLength(128)] string? Username,
    [StringLength(256)] string? Password,
    bool Encrypted = true);

public sealed record MountRequest(
    [Required] [StringLength(64, MinimumLength = 1)] string Name,
    [Required] [StringLength(128)] string Username,
    [StringLength(256)] string? Password);

public sealed record GrantAccessRequest(
    [Required] [StringLength(128)] string TargetUsername,
    [Required] [StringLength(256, MinimumLength = 1)] string TargetPassword,
    [Required] [StringLength(256, MinimumLength = 1)] string GranterPassword);

public sealed record RevokeAccessRequest(
    [Required] [StringLength(128)] string TargetUsername);

public sealed record ChangePasswordRequest(
    [Required] [StringLength(256, MinimumLength = 1)] string OldPassword,
    [Required] [StringLength(256, MinimumLength = 8)] string NewPassword);

/// <summary>ボリューム一覧表示用。</summary>
public sealed record VolumeInfo(
    string Name, bool IsMounted, bool Encrypted, string OwnerUser,
    DateTimeOffset CreatedAt, IReadOnlyList<string> AuthorizedUsers,
    string EncryptionMode = "server",
    string CipherAlgorithm = "aes-256-xts",
    int KeySize = 256,
    IReadOnlyList<string> AuthorizedGroups = null!,
    bool IsHome = false,
    Dictionary<string, string>? UserWrapTypes = null);

/// <summary>ボリューム操作の業務エラー。</summary>
public sealed class VolumeException(string message) : Exception(message);

/// <summary>E2EE wrapped key 取得レスポンス（GetWrappedKey API）。</summary>
public sealed record WrappedKeyResponse(
    string WrapType,
    KdfResponse Kdf,
    WrappedMasterKeyResponse WrappedMasterKey,
    string? EphemeralPublicKey,
    int ChunkSize);

public sealed record KdfResponse(string Algorithm, int Iterations, string Salt);

public sealed record WrappedMasterKeyResponse(string Algorithm, string Nonce, string Ciphertext, string Tag);
