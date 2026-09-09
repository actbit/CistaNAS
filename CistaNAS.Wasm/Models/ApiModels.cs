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
    /// <summary>"argon2id"（Argon2id+PBKDF2 合成）or "argon2id-raw"（Argon2id 単独）or "pbkdf2-sha256"（レガシー単段）。</summary>
    public string Algorithm { get; set; } = "pbkdf2-sha256";
    /// <summary>argon2id: 後段 PBKDF2 の反復数。argon2id-raw: 不使用（0）。pbkdf2-sha256: PBKDF2 反復数。</summary>
    public int Iterations { get; set; }
    /// <summary>Argon2id 前段のメモリ量（KiB）。レガシー pbkdf2 では 0。</summary>
    public int MemoryKiB { get; set; }
    /// <summary>Argon2id 前段のパス数（t）。レガシー pbkdf2 では 0。</summary>
    public int TimeCost { get; set; }
    /// <summary>Argon2id 前段の並列度。レガシー pbkdf2 では 0。</summary>
    public int Parallelism { get; set; }
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
public sealed record E2eeCreateFileRequest(
    string EncryptedName, long EncryptedLength, int ChunkCount,
    int KeyEpoch = 0, WrappedAeadKeyParams? WrappedFileKey = null, string? FileId = null);
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
    public string? WriteLeaseToken { get; set; }
    /// <summary>crypto format v2: このファイルの鍵 epoch。0 = v1 形式（masterKey 派生 fileKey）。</summary>
    public int KeyEpoch { get; set; }
    /// <summary>crypto format v2: per-file DEK を GroupKey[KeyEpoch] でラップしたもの。KeyEpoch == 0 では null。</summary>
    public WrappedAeadKeyParams? WrappedFileKey { get; set; }
}

public sealed record E2eeVolumeStats(long TotalUsedBytes, long UserUsedBytes, long UserQuotaBytes, int TotalFiles, int UserFiles);
public sealed record E2eeSetQuotaRequest(long MaxBytes);
public sealed record E2eeAddWrappedKeyRequest(string Username, UserWrappedKey WrappedMasterKey);
public sealed record AddE2eeWrappedKeysBatchRequest(Dictionary<string, UserWrappedKey> WrappedKeys);

// ---- 共有 E2EE v2（GroupKey epoch / per-file DEK / pinning）----

/// <summary>AEAD ラップされた鍵（algorithm / nonce / ciphertext / tag。JSON は base64）。</summary>
public sealed class WrappedAeadKeyParams
{
    public string Algorithm { get; set; } = "aes-256-gcm";
    public byte[] Nonce { get; set; } = [];
    public byte[] Ciphertext { get; set; } = [];
    public byte[] Tag { get; set; } = [];
}

/// <summary>group-key-info 応答: 自分宛てにラップされた GroupKey（epoch 単位）。</summary>
public sealed record GroupKeyWrapInfoJson(
    int Epoch,
    string WrapType,
    string WrappedKeyAlgorithm,
    byte[] Nonce,
    byte[] Ciphertext,
    byte[] Tag,
    string? EphemeralPublicKey);

/// <summary>group-key-info 応答。共有 v2 未移行ボリュームでは KeyEpoch == 0 / MyGroupKeys 空。</summary>
public sealed record E2eeGroupKeyInfoResponse(
    string VolumeId,
    int KeyEpoch,
    IReadOnlyList<GroupKeyWrapInfoJson> MyGroupKeys,
    bool HasLegacyFiles);

/// <summary>rotate-group-key 要求（revoke 時）。WrappedGroupKeys は remaining members のユーザー名 → wrap。</summary>
public sealed record E2eeRotateGroupKeyRequest(
    int NewEpoch,
    Dictionary<string, UserWrappedKey> WrappedGroupKeys,
    string? RemovedUsername = null);

/// <summary>member-public-keys 応答: remaining members の公開鍵（base64）。</summary>
public sealed record E2eeMemberPublicKeyResponse(string Username, string? PublicKeyBase64);

/// <summary>rewrap-file-keys 要求エントリ: ファイル鍵を現行 epoch の GroupKey に再ラップ。</summary>
public sealed record E2eeRewrapFileKeyEntry(string FileId, int KeyEpoch, WrappedAeadKeyParams WrappedFileKey);
public sealed record E2eeRewrapFileKeysRequest(IReadOnlyList<E2eeRewrapFileKeyEntry> Rewraps);

// ---- グループ ----

public sealed record CreateGroupRequest(string GroupName);
public sealed record AddGroupMemberRequest(string Username);

// ---- ECDH / 招待 ----

public sealed record SetPublicKeyRequest(string PublicKey);
public sealed record CreateGroupE2eeVolumeRequest(string GroupName, UserWrappedKey OwnerWrappedKey, int ChunkSize = 1048576);
public sealed record CreateInvitationRequest(string TargetUsername);
public sealed record AcceptInvitationRequest(string EncryptedPublicKey, string Nonce);
public sealed record StreamTokenRequest(string VolumeName, string FileName);

/// <summary>ラップ鍵取得レスポンス。サーバーは Base64 文字列で返す。</summary>
public sealed record WrappedKeyResponse(
    string WrapType,
    WrappedKeyKdfJson Kdf,
    WrappedKeyParamsJson WrappedMasterKey,
    string? EphemeralPublicKey,
    int ChunkSize);

/// <summary>KDF パラメータ（JSON 用、Salt は Base64 文字列）。argon2id は Argon2id+PBKDF2 合成、argon2id-raw は Argon2id 単独。</summary>
public sealed class WrappedKeyKdfJson
{
    public string Algorithm { get; set; } = "pbkdf2-sha256";
    public int Iterations { get; set; }
    public int MemoryKiB { get; set; }
    public int TimeCost { get; set; }
    public int Parallelism { get; set; }
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
