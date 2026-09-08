using Konscious.Security.Cryptography;

namespace CistaNAS.Shared.Crypto;

/// <summary>
/// Argon2id (RFC 9106) — メモリ困難性パスワード KDF。
/// PBKDF2 と異なりメモリを大量消費するため GPU / ASIC による総当たりを困難にする。
/// 低レベル実装。PasswordHasher（ログイン）・KeyDerivation / E2eeCrypto（KEK 導出）から呼ばれる。
/// </summary>
public static class Argon2idKdf
{
    /// <summary>Argon2 バージョン 1.3 (0x13)。</summary>
    public const int Version = 0x13;

    /// <summary>
    /// 既定メモリ量（KiB）= 64 MiB。RFC 9106 の低メモリ推奨（64 MiB）に基づく。
    /// デスクトップで約 100ms、モバイルで約 1 秒程度。
    /// </summary>
    public const int DefaultMemoryKiB = 65536;
    /// <summary>既定時間コスト（パス数）。RFC 9106 推奨の t=3 を 1 上乗せ。</summary>
    public const int DefaultTimeCost = 4;
    /// <summary>既定並列度（レーン数）。RFC 9106 推奨の p=4。</summary>
    public const int DefaultParallelism = 4;

    /// <summary>
    /// 未認証リクエストのタイミング均一化（ダミー計算）用の軽量プロファイル。
    /// 未認証リクエストで本パラメータのメモリを奪わせないため、本番プロファイルより軽量。
    /// </summary>
    public const int DummyMemoryKiB = 16384;   // 16 MiB
    public const int DummyTimeCost = 2;
    public const int DummyParallelism = 1;

    /// <summary>検証時に受け入れるメモリ量上限（KiB）。保存済みパラメータ改ざんによるメモリ枯渇 DoS 防止。</summary>
    public const int MaxVerifyMemoryKiB = 1_048_576; // 1 GiB
    /// <summary>検証時に受け入れる時間コスト上限（PBKDF2 の MaxVerifyIterations に相当）。</summary>
    public const int MaxVerifyTimeCost = 1_000_000;
    /// <summary>検証時に受け入れる並列度上限。</summary>
    public const int MaxVerifyParallelism = 64;

    /// <summary>
    /// Argon2id で <paramref name="length"/> バイトの鍵を導出する。
    /// </summary>
    /// <param name="timeCost">パス数（t）</param>
    /// <param name="memoryKiB">メモリ量（KiB）</param>
    /// <param name="parallelism">並列度（p）</param>
    /// <param name="secret">オプションの keyed-hash 用 secret（RFC 9106 テストベクトル検証用）</param>
    /// <param name="associatedData">オプションの関連データ（同上）</param>
    public static byte[] Derive(string password, byte[] salt, int timeCost, int memoryKiB, int parallelism, int length,
        byte[]? secret = null, byte[]? associatedData = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        return Derive(System.Text.Encoding.UTF8.GetBytes(password), salt, timeCost, memoryKiB, parallelism, length, secret, associatedData);
    }

    /// <summary><paramref name="password"/> を生バイト列として扱うオーバーロード。</summary>
    public static byte[] Derive(byte[] password, byte[] salt, int timeCost, int memoryKiB, int parallelism, int length,
        byte[]? secret = null, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);
        ValidateParams(timeCost, memoryKiB, parallelism);
        ArgumentOutOfRangeException.ThrowIfLessThan(length, 1);

        return new Argon2id(password)
        {
            Salt = salt,
            KnownSecret = secret,
            AssociatedData = associatedData,
            Iterations = timeCost,
            MemorySize = memoryKiB,
            DegreeOfParallelism = parallelism,
        }.GetBytes(length);
    }

    /// <summary>Argon2 仕様上のパラメータ範囲を検証する（生成・検証共通）。</summary>
    public static void ValidateParams(int timeCost, int memoryKiB, int parallelism)
    {
        // Argon2 仕様: t >= 1, p >= 1, m >= 8*p KiB
        if (timeCost < 1)
            throw new ArgumentOutOfRangeException(nameof(timeCost), "時間コスト（t）は 1 以上である必要があります。");
        if (parallelism is < 1 or > 255)
            throw new ArgumentOutOfRangeException(nameof(parallelism), "並列度（p）は 1〜255 である必要があります。");
        if (memoryKiB < 8 * parallelism)
            throw new ArgumentOutOfRangeException(nameof(memoryKiB), $"メモリ量は {8 * parallelism} KiB 以上（8 × 並列度）である必要があります。");
    }

    /// <summary>
    /// 検証時に受け入れ可能なパラメータか（上限チェック）。
    /// 保存済みハッシュ / ボリュームヘッダに埋め込まれたパラメータをそのまま実行すると
    /// 改ざんによる CPU・メモリ枯渇 DoS になるため、検証前に呼ぶこと。
    /// </summary>
    public static bool IsWithinVerifyLimits(int timeCost, int memoryKiB, int parallelism)
        => timeCost is >= 1 and <= MaxVerifyTimeCost
        && memoryKiB is >= 1 and <= MaxVerifyMemoryKiB
        && parallelism is >= 1 and <= MaxVerifyParallelism;
}
