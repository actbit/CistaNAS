using CistaNAS.Web.Volume;

namespace CistaNAS.Web.Models;

/// <summary>ボリューム内のファイルメタデータ。</summary>
public sealed class FileMetadata
{
    public required string Name { get; set; }
    public long Offset { get; set; }
    public long Length { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }
}

public sealed record ListFilesResponse(IReadOnlyList<FileMetadata> Files);
public sealed record FileUploadRequest(string VolumeName, string FileName, Stream Content, long ContentLength);
public sealed record FileDownloadResponse(Stream Stream, string FileName, long Length);

/// <summary>ファイル操作の業務エラー。</summary>
public sealed class FileServiceException(string message) : Exception(message);

// ---- E2EE 関連モデル ----

/// <summary>E2EE ボリューム作成リクエスト（クライアントからラップ済み鍵を受け取る）。</summary>
public sealed record E2eeCreateVolumeRequest(
    string VolumeName,
    string Username,
    VolumeHeader.UserWrappedKey WrappedMasterKey,
    int ChunkSize = 1048576);

/// <summary>E2EE ファイルカタログエントリ。</summary>
public sealed class E2eeFileEntry
{
    public required string FileId { get; set; }
    public required string EncryptedName { get; set; }
    public long Offset { get; set; }
    public long EncryptedLength { get; set; }
    public int ChunkCount { get; set; }
    public List<int> ChunkSizes { get; set; } = [];
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }
}

public sealed record E2eeCreateFileRequest(string EncryptedName, long EncryptedLength, int ChunkCount);
public sealed record E2eeFinalizeFileRequest(long ActualEncryptedLength);
public sealed record E2eeListFilesResponse(IReadOnlyList<E2eeFileEntry> Files);
public sealed record E2eeMountResponse(int ChunkSize, string EncryptionMode);

/// <summary>E2EE 共有時の鍵追加リクエスト。</summary>
public sealed record E2eeAddWrappedKeyRequest(string Username, VolumeHeader.UserWrappedKey WrappedMasterKey);

/// <summary>E2EE カタログ（永続化用）。</summary>
public sealed class E2eeCatalog
{
    public Dictionary<string, E2eeFileEntry> Files { get; set; } = new(StringComparer.Ordinal);
}

// ---- ECDH 鍵交換・招待関連 DTO ----

public sealed record SetPublicKeyRequest(string PublicKey);
public sealed record CreateGroupE2eeVolumeRequest(string GroupName, VolumeHeader.UserWrappedKey OwnerWrappedKey, int ChunkSize = 1048576);
public sealed record AddE2eeWrappedKeysBatchRequest(Dictionary<string, VolumeHeader.UserWrappedKey> WrappedKeys);
public sealed record CreateInvitationRequest(string TargetUsername);
public sealed record AcceptInvitationRequest(string InvitationId, string EncryptedPublicKey, string Nonce);
public sealed record InvitationResponse(string InvitationId, string InviterUsername, DateTimeOffset CreatedAt);
