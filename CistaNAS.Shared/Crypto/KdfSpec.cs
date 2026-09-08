namespace CistaNAS.Shared.Crypto;

/// <summary>
/// パスワードベース KDF のパラメータ一式。
/// ボリュームヘッダの KdfParams・API の kdf フィールドと対応し、
/// 全クライアント（.NET / ブラウザ e2ee.js / モバイル）で同一の導出を行う。
/// </summary>
/// <remarks>
/// Algorithm == "argon2id"（現行標準）は合成 KDF を意味する:
/// <c>KEK = PBKDF2-SHA256( Argon2id(password, salt, TimeCost, MemoryKiB, Parallelism), salt, Iterations, len )</c>
/// - MemoryKiB / TimeCost / Parallelism = 前段 Argon2id のメモリ量（KiB）・パス数（t）・並列度。
///   すべてヘッダに永続化する（後から既定値を変更しても既存ボリュームの検証が壊れないようにするため）
/// - Iterations = 後段 PBKDF2 の反復数（Argon2id 実装が将来破られた場合の CPU 困難性バックストップ）
/// Algorithm == "pbkdf2-sha256"（レガシー）は単段 PBKDF2。MemoryKiB / TimeCost / Parallelism は 0。
/// </remarks>
public sealed record KdfSpec(
    string Algorithm,
    int Iterations,
    int MemoryKiB,
    int Parallelism,
    int TimeCost = Argon2idKdf.DefaultTimeCost)
{
    /// <summary>Argon2id + PBKDF2 合成 KDF（現行標準）。</summary>
    public const string Argon2id = "argon2id";
    /// <summary>PBKDF2-SHA256 単段（レガシー。既存ボリュームの検証専用）。</summary>
    public const string Pbkdf2Sha256 = "pbkdf2-sha256";

    /// <summary>新規作成時の既定 PBKDF2 後段反復数（Argon2id 合成の後段）。</summary>
    public const int DefaultPbkdf2StageIterations = 600_000;

    /// <summary>新規作成時の既定: Argon2id(m=64MiB, t=4, p=4) + PBKDF2(600k) 合成。</summary>
    public static KdfSpec DefaultArgon2id { get; } =
        new(Argon2id, DefaultPbkdf2StageIterations, Argon2idKdf.DefaultMemoryKiB, Argon2idKdf.DefaultParallelism);

    /// <summary>レガシー PBKDF2 単段スペック（既存データの検証用）。</summary>
    public static KdfSpec LegacyPbkdf2(int iterations) => new(Pbkdf2Sha256, iterations, 0, 0);

    public bool IsArgon2id => string.Equals(Algorithm, Argon2id, StringComparison.Ordinal);
    public bool IsPbkdf2 => string.Equals(Algorithm, Pbkdf2Sha256, StringComparison.Ordinal);

    /// <summary>Argon2id スペックとして検証可能か（検証上限込み）。</summary>
    public bool IsValidArgon2id() =>
        IsArgon2id && Argon2idKdf.IsWithinVerifyLimits(TimeCost, MemoryKiB, Parallelism);
}
