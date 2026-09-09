using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
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

    /// <summary>チャンクの保存オブジェクト ID。旧カタログではファイル名を使用する。</summary>
    public string? ChunkObjectId { get; set; }

    /// <summary>
    /// サーバー側暗号化チャンクのファイルスコープ鍵導出用ソルト（base64 16 バイト）。
    /// chunkIndex はファイル相対のため、マスターキー直用だと別ファイル同一位置で
    /// XTS tweak が衝突する。これを防ぐため新規書き込み時に生成する。
    /// null は旧形式（レガシー: マスターキー直接使用）として復号する。
    /// </summary>
    public string? KeySalt { get; set; }
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

    /// <summary>各チャンクの暗号化リビジョン。差分上書きで AES-GCM の nonce を一意に保つために使用。
    /// 0=初回（従来フォーマットと後方互換）。要素不足/空は 0 扱い。クライアントは復号時にこの revision を nonce 導出に使う。</summary>
    public List<int> ChunkRevisions { get; set; } = [];

    /// <summary>
    /// crypto format v2: 各チャンクを暗号化したときの keyEpoch。ChunkRevisions と対で復号時に使う
    /// （v2 チャンクの nonce / AAD は keyEpoch を bind するため、rotation 後の rewrap —
    /// entry.KeyEpoch のみ更新でチャンク本体不変 — でも旧チャンクを正しく復号できるようにする）。
    /// 要素不足は entry.KeyEpoch 扱い。v1 ファイル（KeyEpoch == 0）ではすべて 0。
    /// </summary>
    public List<int> ChunkKeyEpochs { get; set; } = [];

    /// <summary>各チャンクが参照する不変オブジェクトID。要素不足は旧形式の FileId を使用する。</summary>
    public List<string> ChunkObjectIds { get; set; } = [];

    /// <summary>
    /// このファイルの鍵 epoch。0 = v1 形式（masterKey 派生 fileKey、単独 E2EE）。
    /// ≥1 = crypto format v2（per-file DEK、強化 AAD）。共有 E2EE で新規作成されるファイルは
    /// ボリュームの現行 KeyEpoch で作成される。
    /// </summary>
    public int KeyEpoch { get; set; }

    /// <summary>
    /// crypto format v2: per-file DEK（32B）を GroupKey[KeyEpoch] で AES-256-GCM ラップしたもの。
    /// AAD に volumeId / fileId / keyEpoch を bind 済み。KeyEpoch == 0 の場合は null。
    /// GroupKey ローテーション時はこの値の再ラップのみで移行する（チャンク本体は不変）。
    /// </summary>
    public VolumeHeader.WrappedKey? WrappedFileKey { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }

    /// <summary>ファイルを作成したユーザー（JWT から抽出）。</summary>
    public string OwnerUsername { get; set; } = "";

    /// <summary>作成APIの応答でのみ返す初期書き込みリース。カタログには保存しない。</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? WriteLeaseToken { get; set; }
}

public sealed record E2eeCreateFileRequest(
    [Required] string EncryptedName,
    [Range(0, long.MaxValue)] long EncryptedLength,
    [Range(1, 100000)] int ChunkCount,
    /// <summary>crypto format v2: このファイルの鍵 epoch（0 = v1 形式）。ボリュームの現行 epoch 以下であること。</summary>
    int KeyEpoch = 0,
    /// <summary>crypto format v2: per-file DEK を GroupKey[KeyEpoch] でラップしたもの。KeyEpoch ≥ 1 で必須。</summary>
    VolumeHeader.WrappedKey? WrappedFileKey = null,
    /// <summary>
    /// crypto format v2: クライアント生成 fileId（GUID "N" 形式、任意）。
    /// v2 では WrappedFileKey の AAD に fileId が bind されるため、wrap を先に行えるよう
    /// クライアント側で fileId を決めて 1 リクエストで作成できる。未指定時はサーバー生成。
    /// </summary>
    string? FileId = null);

/// <summary>crypto format v2: ファイル鍵の再ラップ（GroupKey ローテーション / epoch migration）。</summary>
public sealed record E2eeRewrapFileKeyEntry(
    [Required] string FileId,
    [Range(1, int.MaxValue)] int KeyEpoch,
    [Required] VolumeHeader.WrappedKey WrappedFileKey);

public sealed record E2eeRewrapFileKeysRequest(
    [Required] IReadOnlyList<E2eeRewrapFileKeyEntry> Rewraps);

/// <summary>crypto format v2: GroupKey ローテーション（revoke によるメンバー縮小）。</summary>
public sealed record E2eeRotateGroupKeyRequest(
    [Range(1, int.MaxValue)] int NewEpoch,
    /// <summary>remaining members 宛てのラップ済み GroupKey（削除されたメンバーを含めてはならない）。</summary>
    [Required] Dictionary<string, VolumeHeader.UserWrappedKey> WrappedGroupKeys,
    /// <summary>このローテーションで剥奪するユーザー（全 epoch の wraps と UserKeys から削除）。null 可（revoke 無しの再ラップ）。</summary>
    string? RemovedUsername = null);

/// <summary>crypto format v2: 自分宛てにラップされた GroupKey（epoch 単位）。</summary>
public sealed record GroupKeyWrapResponse(
    int Epoch,
    string WrapType,
    string WrappedKeyAlgorithm,
    string Nonce,
    string Ciphertext,
    string Tag,
    string? EphemeralPublicKey);

/// <summary>crypto format v2: 共有 v2 ボリュームの鍵状態（マウント時 / rotation 時に使用）。</summary>
public sealed record E2eeGroupKeyInfoResponse(
    string VolumeId,
    int KeyEpoch,
    IReadOnlyList<GroupKeyWrapResponse> MyGroupKeys,
    /// <summary>ボリューム内に現行 epoch 未満のファイルが残っているか（migration 未完了の目安）。</summary>
    bool HasLegacyFiles);

/// <summary>crypto format v2: remaining members と公開鍵（owner が rotation 用に取得）。</summary>
public sealed record E2eeMemberPublicKeyResponse(string Username, string? PublicKeyBase64);
public sealed record E2eeFinalizeFileRequest(
    [Range(0, long.MaxValue)] long ActualEncryptedLength,
    int? ChunkCount = null);
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

/// <summary>
/// 暗号化設定更新リクエスト (WASM 用)。Kdf* は新規ボリュームの鍵導出スペック:
/// KdfAlgorithm=="argon2id"（既定）は Argon2id(MemoryKiB/TimeCost/Parallelism) + PBKDF2(Iterations) の合成 KDF、
/// "argon2id-raw" は Argon2id 単独（Iterations 不使用）。
/// </summary>
public sealed record UpdateEncryptionSettingsRequest(
    string DefaultEncryptionMode = "server",
    int E2eeChunkSize = 1048576,
    string KdfAlgorithm = "argon2id",
    int KdfIterations = 600_000,
    int KdfMemoryKiB = 65536,
    int KdfTimeCost = 4,
    int KdfParallelism = 4,
    int SectorSize = 4096);
