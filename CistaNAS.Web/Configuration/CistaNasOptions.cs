using System.ComponentModel.DataAnnotations;

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

    /// <summary>CORS で許可するオリジンリスト。空なら CORS ポリシーは適用されない（same-origin のみ）。</summary>
    public List<string> CorsAllowedOrigins { get; set; } = [];

    /// <summary>ストリーミングトークンの TTL（秒）。デフォルト 30 秒。</summary>
    [Range(1, int.MaxValue, ErrorMessage = "StreamingTokenTtlSeconds は 1 以上である必要があります。")]
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

    /// <summary>ログインパスワードハッシュの PBKDF2 反復回数。</summary>
    [Range(100_000, 10_000_000)]
    public int Pbkdf2Iterations { get; set; } = 210_000;
}

public sealed class VolumeOptions
{
    /// <summary>AES-XTS のデータユニット(セクタ)サイズ。16 の倍数であること。</summary>
    [Range(512, 4096)]
    public int SectorSize { get; set; } = 4096;

    /// <summary>ボリュームパスワードからマスター鍵を導出する際の PBKDF2 反復回数。</summary>
    [Range(100_000, 10_000_000)]
    public int KdfIterations { get; set; } = 310_000;

    /// <summary>新規ボリューム作成時のデフォルト暗号化モード。"server" | "e2ee" | "none"。</summary>
    public string DefaultEncryptionMode { get; set; } = "server";

    /// <summary>E2EE ボリュームのデフォルトチャンクサイズ（バイト）。</summary>
    [Range(65536, 16777216)]
    public int E2eeChunkSize { get; set; } = 1048576;
}
