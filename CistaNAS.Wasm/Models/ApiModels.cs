namespace CistaNAS.Wasm.Models;

/// <summary>ログイン要求。</summary>
public sealed record LoginRequest(string Username, string Password);

/// <summary>ログイン成功時の JWT レスポンス。</summary>
public sealed record LoginResponse(string AccessToken, string TokenType, DateTimeOffset ExpiresAt);

/// <summary>初期セットアップ要求。</summary>
public sealed record SetupRequest(string Username, string Password);

/// <summary>パスワード変更要求。</summary>
public sealed record ChangePasswordRequest(string OldPassword, string NewPassword);

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

/// <summary>ボリューム作成要求。</summary>
public sealed record CreateVolumeRequest(string Name, string? Username = null, string? Password = null, bool Encrypted = true);

/// <summary>ボリュームマウント要求。</summary>
public sealed record MountRequest(string Name, string Username, string? Password = null);

/// <summary>アクセス権付与要求。</summary>
public sealed record GrantAccessRequest(string TargetUsername, string TargetPassword, string GranterPassword);

/// <summary>アクセス権剥奪要求。</summary>
public sealed record RevokeAccessRequest(string TargetUsername);

/// <summary>ボリューム内のファイルメタデータ。</summary>
public sealed class FileMetadata
{
    public required string Name { get; set; }
    public long Offset { get; set; }
    public long Length { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }
    public int ChunkCount { get; set; }
    public List<int> ChunkSizes { get; set; } = [];
    public bool IsChunked => ChunkCount > 0;
}

public sealed record ListFilesResponse(IReadOnlyList<FileMetadata> Files);

// ---- E2EE ----

/// <summary>ラップ済み鍵パラメータ。</summary>
public sealed class UserWrappedKey
{
    public string WrapType { get; set; } = "password";
    public KdfParams Kdf { get; set; } = new();
    public WrappedKeyParams WrappedMasterKey { get; set; } = new();
    public byte[]? EphemeralPublicKey { get; set; }
}

public sealed class KdfParams
{
    public string Algorithm { get; set; } = "pbkdf2-sha256";
    public int Iterations { get; set; }
    public byte[] Salt { get; set; } = [];
}

public sealed class WrappedKeyParams
{
    public string Algorithm { get; set; } = "aes-256-gcm";
    public byte[] Nonce { get; set; } = [];
    public byte[] Ciphertext { get; set; } = [];
    public byte[] Tag { get; set; } = [];
}

public sealed record E2eeCreateVolumeRequest(string VolumeName, string? Username, UserWrappedKey WrappedMasterKey, int ChunkSize = 1048576);
public sealed record E2eeCreateFileRequest(string EncryptedName, long EncryptedLength, int ChunkCount);
public sealed record E2eeFinalizeFileRequest(long ActualEncryptedLength);
public sealed record E2eeListFilesResponse(IReadOnlyList<E2eeFileEntry> Files);
public sealed record E2eeMountResponse(int ChunkSize, string EncryptionMode);

public sealed class E2eeFileEntry
{
    public required string FileId { get; set; }
    public required string EncryptedName { get; set; }
    public long Offset { get; set; }
    public long EncryptedLength { get; set; }
    public int ChunkCount { get; set; }
    public List<int> ChunkSizes { get; set; } = [];
    public List<string> ChunkHashes { get; set; } = [];
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }
    public string OwnerUsername { get; set; } = "";
}

public sealed record E2eeVolumeStats(long TotalUsedBytes, long UserUsedBytes, long UserQuotaBytes, int TotalFiles, int UserFiles);
public sealed record E2eeSetQuotaRequest(long MaxBytes);
public sealed record E2eeAddWrappedKeyRequest(string Username, UserWrappedKey WrappedMasterKey);
public sealed record AddE2eeWrappedKeysBatchRequest(Dictionary<string, UserWrappedKey> WrappedKeys);

// ---- グループ ----

public sealed record CreateGroupRequest(string GroupName);
public sealed record AddGroupMemberRequest(string Username);

// ---- ECDH / 招待 ----

public sealed record SetPublicKeyRequest(string PublicKey);
public sealed record CreateGroupE2eeVolumeRequest(string GroupName, UserWrappedKey OwnerWrappedKey, int ChunkSize = 1048576);
public sealed record CreateInvitationRequest(string TargetUsername);
public sealed record AcceptInvitationRequest(string InvitationId, string EncryptedPublicKey, string Nonce);
public sealed record StreamTokenRequest(string VolumeName, string FileName);

/// <summary>ラップ鍵取得レスポンス。サーバーは Base64 文字列で返す。</summary>
public sealed record WrappedKeyResponse(
    string WrapType,
    WrappedKeyKdfJson Kdf,
    WrappedKeyParamsJson WrappedMasterKey,
    string? EphemeralPublicKey,
    int ChunkSize);

/// <summary>KDF パラメータ（JSON 用、Salt は Base64 文字列）。</summary>
public sealed class WrappedKeyKdfJson
{
    public string Algorithm { get; set; } = "pbkdf2-sha256";
    public int Iterations { get; set; }
    public string Salt { get; set; } = "";
}

/// <summary>ラップ済みマスターキーパラメータ（JSON 用、Nonce/Ciphertext/Tag は Base64 文字列）。</summary>
public sealed class WrappedKeyParamsJson
{
    public string Algorithm { get; set; } = "aes-256-gcm";
    public string Nonce { get; set; } = "";
    public string Ciphertext { get; set; } = "";
    public string Tag { get; set; } = "";
}
