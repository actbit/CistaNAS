using System.Security.Cryptography;
using System.Text;

namespace CistaNAS.Shared.Crypto;

/// <summary>
/// ボリュームパスワードからの鍵導出。
/// 現行: Argon2id（メモリ困難性、RFC 9106）。レガシー: PBKDF2-SHA256（既存ボリュームの検証のみ）。
/// 低レベル実装。Volume 層（ボリュームヘッダ）・E2eeCrypto から呼ばれる。
/// </summary>
public static class KeyDerivation
{
    /// <summary>AES-256-XTS のマスター鍵長（K1 32 byte || K2 32 byte）。</summary>
    public const int MasterKeySize = 64;

    public const int SaltSize = 16;

    /// <summary>
    /// ユーザー名を含む結合ソルト（SHA256(username) || salt）を作る。
    /// ユーザー名がソルトの一部 → 同じパスワードでもユーザー違いで別鍵。
    /// e2ee.js deriveKek と同一規約。username が空なら salt 単体。
    /// </summary>
    public static byte[] CombineUserSalt(string? username, byte[] salt)
    {
        if (string.IsNullOrEmpty(username)) return salt;
        byte[] userHash = SHA256.HashData(Encoding.UTF8.GetBytes(username));
        byte[] combinedSalt = new byte[userHash.Length + salt.Length];
        Buffer.BlockCopy(userHash, 0, combinedSalt, 0, userHash.Length);
        Buffer.BlockCopy(salt, 0, combinedSalt, userHash.Length, salt.Length);
        return combinedSalt;
    }

    /// <summary>
    /// パスワードとソルトから <paramref name="length"/> バイトの鍵を導出する（レガシー PBKDF2）。
    /// 既存データの検証専用。新規の鍵導出は <see cref="DeriveKek(string, string, byte[], KdfSpec, int)"/> を使用。
    /// </summary>
    public static byte[] Derive(string password, byte[] salt, int iterations, int length)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        ArgumentNullException.ThrowIfNull(salt);
        // OWASP 推奨: PBKDF2-SHA256 は最低 600,000 回。
        // 極端に低い反復回数はブルートフォース脆弱性を生むため、100,000 回を下限とする。
        const int MinIterations = 100_000;
        if (iterations < MinIterations) throw new ArgumentOutOfRangeException(nameof(iterations), $"PBKDF2 反復回数は {MinIterations} 以上である必要があります。");
        if (length < 1) throw new ArgumentOutOfRangeException(nameof(length));

        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, length);
    }

    /// <summary>
    /// パスワードとソルトから KDF スペックに応じて鍵を導出する（現行エントリポイント）。
    /// argon2id: 合成 KDF = PBKDF2-SHA256( Argon2id(password, salt, t, m, p), salt, Iterations )。
    /// Argon2id がメモリ困難性を、PBKDF2 後段が CPU 困難性のバックストップを担う。
    /// pbkdf2-sha256: レガシー単段（既存ボリュームの検証専用。テスト用の低反復数もここで許容）。
    /// </summary>
    public static byte[] DeriveKek(string username, string password, byte[] salt, KdfSpec spec, int outputLength = 32)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        ArgumentNullException.ThrowIfNull(salt);

        byte[] combinedSalt = CombineUserSalt(username, salt);
        if (spec.IsArgon2id)
        {
            Argon2idKdf.ValidateParams(spec.TimeCost, spec.MemoryKiB, spec.Parallelism);
            if (spec.Iterations < 1)
                throw new ArgumentOutOfRangeException(nameof(spec), "PBKDF2 後段の反復数は 1 以上である必要があります。");

            byte[] argon2Output = Argon2idKdf.Derive(password, combinedSalt, spec.TimeCost, spec.MemoryKiB, spec.Parallelism, 32);
            try
            {
                return Rfc2898DeriveBytes.Pbkdf2(argon2Output, combinedSalt, spec.Iterations, HashAlgorithmName.SHA256, outputLength);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(argon2Output);
            }
        }

        // レガシー PBKDF2-SHA256 単段（既存ボリューム / テスト低反復数の検証用）
        if (spec.Iterations < 1)
            throw new ArgumentOutOfRangeException(nameof(spec), "反復回数は 1 以上である必要があります。");
        return Rfc2898DeriveBytes.Pbkdf2(password, combinedSalt, spec.Iterations, HashAlgorithmName.SHA256, outputLength);
    }

    public static byte[] NewSalt() => RandomNumberGenerator.GetBytes(SaltSize);

    /// <summary>新しいランダムなマスター鍵（64 byte）を生成する。</summary>
    public static byte[] NewMasterKey() => RandomNumberGenerator.GetBytes(MasterKeySize);
}
