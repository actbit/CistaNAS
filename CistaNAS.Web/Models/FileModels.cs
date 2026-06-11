using System.ComponentModel.DataAnnotations;
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

    /// <summary>チャンクモード時のチャンク数。0 なら従来のシーケンシャル配置。</summary>
    public int ChunkCount { get; set; }

    /// <summary>チャンクモード時の各チャンクサイズ。ChunkCount と要素数が一致する。</summary>
    public List<int> ChunkSizes { get; set; } = [];

    /// <summary>チャンクモードで保存されているか。</summary>
    public bool IsChunked => ChunkCount > 0;
}

public sealed record ListFilesResponse(IReadOnlyList<FileMetadata> Files);
public sealed record FileUploadRequest(string VolumeName, string FileName, Stream Content, long ContentLength);
public sealed record FileDownloadResponse(Stream Stream, string FileName, long Length, string? ContentType = null);

/// <summary>ファイル操作の業務エラー。</summary>
public sealed class FileServiceException(string message) : Exception(message);

// ---- E2EE 関連モデル ----

/// <summary>E2EE ボリューム作成リクエスト（クライアントからラップ済み鍵を受け取る）。</summary>
/// <remarks>Username フィールドは互換性のために残しているが、サーバー側では使用しない（認証済みユーザーをオーナーとする）。</remarks>
public sealed record E2eeCreateVolumeRequest(
    [Required] [StringLength(64, MinimumLength = 1)] string VolumeName,
    [StringLength(128)] string? Username,
    [Required] VolumeHeader.UserWrappedKey WrappedMasterKey,
    [Range(4096, 67108864)] int ChunkSize = 1048576);

/// <summary>E2EE ファイルカタログエントリ。</summary>
public sealed class E2eeFileEntry
{
    public required string FileId { get; set; }
    public required string EncryptedName { get; set; }
    public long Offset { get; set; }
    public long EncryptedLength { get; set; }
    public int ChunkCount { get; set; }
    public List<int> ChunkSizes { get; set; } = [];

    /// <summary>各チャンクの暗号化データの SHA-256 ハッシュ（16進数文字列）。アップロード時に計算。</summary>
    public List<string> ChunkHashes { get; set; } = [];

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }

    /// <summary>ファイルを作成したユーザー（JWT から抽出）。</summary>
    public string OwnerUsername { get; set; } = "";
}

public sealed record E2eeCreateFileRequest(
    [Required] string EncryptedName,
    [Range(0, long.MaxValue)] long EncryptedLength,
    [Range(1, 100000)] int ChunkCount);
public sealed record E2eeFinalizeFileRequest([Range(0, long.MaxValue)] long ActualEncryptedLength);
public sealed record E2eeListFilesResponse(IReadOnlyList<E2eeFileEntry> Files);
public sealed record E2eeMountResponse(int ChunkSize, string EncryptionMode);

/// <summary>E2EE ボリュームの使用量統計。</summary>
public sealed record E2eeVolumeStats(
    long TotalUsedBytes,
    long UserUsedBytes,
    long UserQuotaBytes,
    int TotalFiles,
    int UserFiles);

/// <summary>ユーザークオータ設定リクエスト。</summary>
public sealed record E2eeSetQuotaRequest([Range(0, long.MaxValue)] long MaxBytes);

/// <summary>E2EE 共有時の鍵追加リクエスト。</summary>
public sealed record E2eeAddWrappedKeyRequest(
    [Required] [StringLength(128)] string Username,
    [Required] VolumeHeader.UserWrappedKey WrappedMasterKey);

/// <summary>E2EE カタログ（永続化用）。</summary>
public sealed class E2eeCatalog
{
    public Dictionary<string, E2eeFileEntry> Files { get; set; } = new(StringComparer.Ordinal);
}

// ---- ECDH 鍵交換・招待関連 DTO ----

public sealed record SetPublicKeyRequest([Required] string PublicKey);
public sealed record CreateGroupE2eeVolumeRequest(
    [Required] [StringLength(64, MinimumLength = 1)] string GroupName,
    [Required] VolumeHeader.UserWrappedKey OwnerWrappedKey,
    [Range(4096, 67108864)] int ChunkSize = 1048576);
public sealed record AddE2eeWrappedKeysBatchRequest(
    [Required] Dictionary<string, VolumeHeader.UserWrappedKey> WrappedKeys);
public sealed record CreateInvitationRequest([Required] [StringLength(128)] string TargetUsername);
public sealed record AcceptInvitationRequest(
    [Required] string InvitationId,
    [Required] string EncryptedPublicKey,
    [Required] string Nonce);
public sealed record InvitationResponse(string InvitationId, string InviterUsername, DateTimeOffset CreatedAt);

/// <summary>メディアストリーミングトークン発行リクエスト。</summary>
public sealed record StreamTokenRequest(
    [Required] string VolumeName,
    [Required] string FileName);

/// <summary>ユーザー作成リクエスト (WASM 用)。</summary>
public sealed record CreateUserRequest(
    [Required] string Username,
    [Required] string Password,
    string? Role = "user");

/// <summary>暗号化設定更新リクエスト (WASM 用)。</summary>
public sealed record UpdateEncryptionSettingsRequest(
    string DefaultEncryptionMode = "server",
    int E2eeChunkSize = 1048576,
    int KdfIterations = 310_000,
    int SectorSize = 4096);
