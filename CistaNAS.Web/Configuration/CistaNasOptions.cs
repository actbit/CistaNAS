using System.ComponentModel.DataAnnotations;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Web.Configuration;

/// <summary>
/// CistaNAS 全体の設定。appsettings.json の "CistaNas" セクションにバインドされる。
/// </summary>
public sealed class CistaNasOptions
{
    public const string SectionName = "CistaNas";

    /// <summary>暗号化ボリューム・ジャーナル・ユーザ情報の保存ルート。</summary>
    public string DataRoot { get; set; } = "data";

    public StorageOptions Storage { get; set; } = new();
    public DatabaseOptions Database { get; set; } = new();
    public JwtOptions Jwt { get; set; } = new();
    public AuthOptions Auth { get; set; } = new();
    public VolumeOptions Volume { get; set; } = new();
    public SharingOptions Sharing { get; set; } = new();

    /// <summary>CORS で許可するオリジンリスト。空なら CORS ポリシーは適用されない（same-origin のみ）。</summary>
    public List<string> CorsAllowedOrigins { get; set; } = [];

    /// <summary>
    /// 信頼して X-Forwarded-For / X-Forwarded-Proto を受理するリバースプロキシの IP 一覧。
    /// ループバックは常に信頼される（同一ホスト上の nginx / Caddy は追加設定不要）。
    /// 設定しない場合、プロキシ背後では RemoteIpAddress がプロキシの IP になり、
    /// IP 単位のレート制限が全利用者で共有される。
    /// </summary>
    public List<string> TrustedProxies { get; set; } = [];

    /// <summary>ストリーミングトークンの TTL（秒）。デフォルト 30 秒。</summary>
    [Range(1, 3600, ErrorMessage = "StreamingTokenTtlSeconds は 1 〜 3600 の範囲で指定してください。")]
    public int StreamingTokenTtlSeconds { get; set; } = 30;
}

/// <summary>ユーザー/グループDBのプロバイダ設定。</summary>
public sealed class DatabaseOptions
{
    /// <summary>"sqlite" | "postgresql" | "s3" | "azureblob" | "gcs"。</summary>
    public string Provider { get; set; } = "sqlite";

    /// <summary>PostgreSQL: 接続文字列。SQLite: ファイルパス（null なら DataRoot/cista.db）。</summary>
    public string? ConnectionString { get; set; }

    /// <summary>s3/azureblob/gcs: バケット/コンテナ名。Storage.BucketOrContainer と同じ。</summary>
    public string? BucketOrContainer { get; set; }

    /// <summary>s3: リージョン。azureblob: 接続文字列。gcs: 未使用。</summary>
    public string? RegionOrConnectionString { get; set; }

    /// <summary>s3: エンドポイント上書き（MinIO 等）。</summary>
    public string? EndpointOverride { get; set; }

    /// <summary>オブジェクトストレージ内の DB ファイルパス（デフォルト "cista.db"）。</summary>
    public string? BlobKey { get; set; }
}

/// <summary>メタデータ保存先のプロバイダ設定。</summary>
public sealed class StorageOptions
{
    /// <summary>"local"（デフォルト）, "s3", "azureblob", "gcs"。</summary>
    public string Provider { get; set; } = "local";

    /// <summary>S3: バケット名。Azure: コンテナ名。GCS: バケット名。</summary>
    public string? BucketOrContainer { get; set; }

    /// <summary>S3: リージョン。Azure: 接続文字列。GCS: 未使用（ADC 使用）。</summary>
    public string? RegionOrConnectionString { get; set; }

    /// <summary>S3: エンドポイント上書き（MinIO, LocalStack 等）。</summary>
    public string? EndpointOverride { get; set; }

    /// <summary>バケット/コンテナ内のプレフィックス（例: "instance-1/"）。</summary>
    public string? PathPrefix { get; set; }

    /// <summary>
    /// volume.dat のローカルパス。null の場合は DataRoot を使用。
    /// クラウドデプロイでは永続ボリュームマウントパス（例: /app/data）を指定。
    /// </summary>
    public string? VolumeDataPath { get; set; }
}

public sealed class JwtOptions
{
    public string Issuer { get; set; } = "CistaNAS";
    public string Audience { get; set; } = "CistaNAS";

    /// <summary>
    /// HMAC-SHA256 署名鍵。未設定時は起動ごとにランダム生成（＝再起動で全トークン失効）。
    /// </summary>
    public string? SigningKey { get; set; }

    [Range(1, 1440)]
    public int AccessTokenMinutes { get; set; } = 60;
}

public sealed class AuthOptions
{
    /// <summary>users.json が無い場合に作成する初期管理者名。</summary>
    public string DefaultAdminUser { get; set; } = "admin";

    /// <summary>初期管理者パスワード。未設定時はランダム生成しログへ出力。</summary>
    public string? DefaultAdminPassword { get; set; }

    /// <summary>ログインパスワードハッシュの Argon2id メモリ量（KiB）。既定 64 MiB（RFC 9106 低メモリ推奨ベース）。</summary>
    [Range(8192, 1_048_576)]
    public int Argon2MemoryKiB { get; set; } = 65536;

    /// <summary>ログインパスワードハッシュの Argon2id 時間コスト（パス数）。</summary>
    [Range(1, 32)]
    public int Argon2TimeCost { get; set; } = 4;

    /// <summary>ログインパスワードハッシュの Argon2id 並列度（レーン数）。</summary>
    [Range(1, 16)]
    public int Argon2Parallelism { get; set; } = 4;

    /// <summary>
    /// （レガシー）旧 PBKDF2 ログインハッシュの反復回数。新規ハッシュは Argon2id を使用するため不使用。
    /// 既存の appsettings.json / cista-settings.json との互換のため残置。
    /// </summary>
    [Range(600_000, 10_000_000)]
    public int Pbkdf2Iterations { get; set; } = 600_000;

    /// <summary>
    /// （レガシー）WebDAV Basic 認証ダミーハッシュ用 PBKDF2 反復回数。Argon2id 移行後は不使用。
    /// 既存設定ファイルとの互換のため残置。
    /// </summary>
    [Range(10_000, 600_000)]
    public int WebDavPbkdf2Iterations { get; set; } = 100_000;

    /// <summary>
    /// WebDAV Basic 認証の成功資格情報キャッシュ秒数。Argon2id 検証は 1 回あたり 64 MiB 相当の
    /// メモリを消費するため、同一資格情報でのリクエスト毎の再検証をこの TTL 内では省略する。0 で無効化。
    /// </summary>
    [Range(0, 86400)]
    public int WebDavAuthCacheSeconds { get; set; } = 600;

    /// <summary>
    /// WebDAV のレート制限（1 IP あたりの req/min）。WebDAV は 1 操作で多数のリクエストを
    /// 発行するため、認証エンドポイント（10/min）より大幅に緩い値。下限 60 にクランプ。
    /// </summary>
    [Range(60, 100000)]
    public int WebDavRequestsPerMinute { get; set; } = 600;

    /// <summary>
    /// 一般 REST API（"api" ポリシー、/api/v1 volumes・e2ee 等）のレート制限
    /// （1 IP あたりの req/min）。統合テスト（Aspire）では 1 アプリ・1 IP に全テストクラスが
    /// 直列に大量リクエストを送るため緩和できる。0 で無効化は不可（DoS 対策のため下限 10）。
    /// </summary>
    [Range(10, 100000)]
    public int ApiRateLimitPerMinute { get; set; } = 100;

    /// <summary>
    /// WebDAV Basic 認証の失敗スロットル（1 IP あたり 1 分間の失敗許容回数）。
    /// 超過した IP は Argon2id 検証（1 回あたり 64 MiB 相当のメモリ）を実行せず即座に 401 を返す。
    /// webdav ポリシー（600 req/min）は正常操作用であり、認証失敗への絞りが無いと
    /// Basic 総当たりがログインエンドポイント比 60 倍の速度で攻撃可能だったため追加。0 で無効化。
    /// </summary>
    [Range(0, 100000)]
    public int WebDavFailedAuthLimitPerMinute { get; set; } = 10;

    /// <summary>
    /// JWT の SecurityStamp 検証結果のキャッシュ秒数。検証はリクエスト毎の DB 往復を伴うため、
    /// (username, stamp) をキーにこの TTL 内の再検証を省略する。stamp はパスワード / ロール変更・
    /// ユーザー削除で更新されるため、失効遅延はこの TTL が上限。0 でキャッシュ無効（毎回検証）。
    /// </summary>
    [Range(0, 86400)]
    public int JwtSecurityStampCacheSeconds { get; set; } = 300;

    /// <summary>
    /// 認証エンドポイント（ログイン等）のレート制限（1 IP あたり 1 分間の許容リクエスト数）。
    /// "auth" ポリシーの PermitLimit。統合テスト（Aspire）では多数のユーザーを連続作成するため
    /// 緩和できる。0 で無効化は不可（総当たり対策のため下限 10）。
    /// </summary>
    [Range(10, 100000)]
    public int AuthRateLimitPerMinute { get; set; } = 10;
}

/// <summary>サーバー全体の共有機能設定。</summary>
public sealed class SharingOptions
{
    /// <summary>
    /// サーバー全体で共有機能（E2EE 共有・招待・グループ共有・ECDH identity セットアップ）を有効化するか。
    /// false でも revoke 等のセキュリティ操作は常に許可され、private E2EE は影響を受けない。
    /// </summary>
    public bool Enabled { get; set; } = true;
}

public sealed class VolumeOptions
{
    /// <summary>AES-XTS のデータユニット(セクタ)サイズ。16 の倍数であること。</summary>
    [Range(512, 4096)]
    public int SectorSize { get; set; } = 4096;

    /// <summary>
    /// 新規ボリュームの KDF 種別。"argon2id"（Argon2id+PBKDF2 合成、既定）or "argon2id-raw"（Argon2id 単独）。
    /// ヘッダに永続化されるため、変更しても既存ボリュームの検証には影響しない。
    /// </summary>
    public string KdfAlgorithm { get; set; } = KdfSpec.Argon2id;

    /// <summary>
    /// ボリュームパスワードからの鍵導出のうち後段 PBKDF2 の反復数。
    /// KdfAlgorithm == "argon2id"（合成）のときのみ使用（"argon2id-raw" では不使用）。
    /// ヘッダに永続化されるため、変更しても既存ボリュームの検証には影響しない。
    /// </summary>
    [Range(600_000, 10_000_000)]
    public int KdfIterations { get; set; } = 600_000;

    /// <summary>新規ボリュームの Argon2id 前段メモリ量（KiB）。既定 64 MiB。</summary>
    [Range(8192, 1_048_576)]
    public int KdfMemoryKiB { get; set; } = 65536;

    /// <summary>新規ボリュームの Argon2id 前段パス数（t）。</summary>
    [Range(1, 32)]
    public int KdfTimeCost { get; set; } = 4;

    /// <summary>新規ボリュームの Argon2id 前段並列度。</summary>
    [Range(1, 16)]
    public int KdfParallelism { get; set; } = 4;

    /// <summary>新規ボリューム作成時にヘッダへ永続化する KDF スペック。</summary>
    public KdfSpec ToKdfSpec() =>
        string.Equals(KdfAlgorithm, KdfSpec.Argon2idRaw, StringComparison.Ordinal)
            ? new KdfSpec(KdfSpec.Argon2idRaw, 0, KdfMemoryKiB, KdfParallelism, KdfTimeCost)
            : new KdfSpec(KdfSpec.Argon2id, KdfIterations, KdfMemoryKiB, KdfParallelism, KdfTimeCost);

    /// <summary>新規ボリューム作成時のデフォルト暗号化モード。"server" | "e2ee" | "none"。</summary>
    public string DefaultEncryptionMode { get; set; } = "server";

    /// <summary>E2EE ボリュームのデフォルトチャンクサイズ（バイト）。</summary>
    [Range(65536, 16777216)]
    public int E2eeChunkSize { get; set; } = 1048576;

    /// <summary>チャンクストレージモード。"local" は常に volume.dat、"auto" は S3 provider 使用時にチャンクモード。</summary>
    public string ChunkStorage { get; set; } = "local";

    /// <summary>チャンクモード時のサーバー側チャンクサイズ（バイト）。4 MiB デフォルト。</summary>
    [Range(1048576, 67108864)]
    public int ServerChunkSize { get; set; } = 4194304;

    /// <summary>
    /// 1 ファイルの最大サイズ（バイト）。UPLOAD（全体 PUT）と PATCH（差分書き込み）の
    /// offset + 長さ に対して検査する。PATCH の巨大 offset によるディスク枯渇
    /// （sparse 埋めで大量 I/O）を防ぐ上限。既定 1 TiB。
    /// </summary>
    [Range(1, 1L << 50)]
    public long MaxFileSizeBytes { get; set; } = 1L << 40;
}
