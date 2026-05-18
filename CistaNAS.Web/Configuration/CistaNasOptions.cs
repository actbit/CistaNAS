namespace CistaNAS.Web.Configuration;

/// <summary>
/// CistaNAS 全体の設定。appsettings.json の "CistaNas" セクションにバインドされる。
/// </summary>
public sealed class CistaNasOptions
{
    public const string SectionName = "CistaNas";

    /// <summary>暗号化ボリューム・ジャーナル・ユーザ情報の保存ルート。</summary>
    public string DataRoot { get; set; } = "data";

    public JwtOptions Jwt { get; set; } = new();
    public AuthOptions Auth { get; set; } = new();
    public VolumeOptions Volume { get; set; } = new();
}

public sealed class JwtOptions
{
    public string Issuer { get; set; } = "CistaNAS";
    public string Audience { get; set; } = "CistaNAS";

    /// <summary>
    /// HMAC-SHA256 署名鍵。未設定時は起動ごとにランダム生成（＝再起動で全トークン失効）。
    /// </summary>
    public string? SigningKey { get; set; }

    public int AccessTokenMinutes { get; set; } = 60;
}

public sealed class AuthOptions
{
    /// <summary>users.json が無い場合に作成する初期管理者名。</summary>
    public string DefaultAdminUser { get; set; } = "admin";

    /// <summary>初期管理者パスワード。未設定時はランダム生成しログへ出力。</summary>
    public string? DefaultAdminPassword { get; set; }

    /// <summary>ログインパスワードハッシュの PBKDF2 反復回数。</summary>
    public int Pbkdf2Iterations { get; set; } = 210_000;
}

public sealed class VolumeOptions
{
    /// <summary>AES-XTS のデータユニット(セクタ)サイズ。16 の倍数であること。</summary>
    public int SectorSize { get; set; } = 4096;

    /// <summary>ボリュームパスワードからマスター鍵を導出する際の PBKDF2 反復回数。</summary>
    public int KdfIterations { get; set; } = 310_000;

    /// <summary>新規ボリューム作成時のデフォルト暗号化モード。"server" | "e2ee" | "none"。</summary>
    public string DefaultEncryptionMode { get; set; } = "server";

    /// <summary>E2EE ボリュームのデフォルトチャンクサイズ（バイト）。</summary>
    public int E2eeChunkSize { get; set; } = 1048576;
}
