using System.Security.Cryptography;

namespace CistaNAS.Shared.Crypto;

/// <summary>
/// ボリュームパスワードからの鍵導出（PBKDF2-SHA256）。
/// 低レベル実装。Volume 層（ボリュームヘッダ）から呼ばれる。
/// </summary>
public static class KeyDerivation
{
    /// <summary>AES-256-XTS のマスター鍵長（K1 32 byte || K2 32 byte）。</summary>
    public const int MasterKeySize = 64;

    public const int SaltSize = 16;

    /// <summary>
    /// パスワードとソルトから <paramref name="length"/> バイトの鍵を導出する。
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

    public static byte[] NewSalt() => RandomNumberGenerator.GetBytes(SaltSize);

    /// <summary>新しいランダムなマスター鍵（64 byte）を生成する。</summary>
    public static byte[] NewMasterKey() => RandomNumberGenerator.GetBytes(MasterKeySize);
}
