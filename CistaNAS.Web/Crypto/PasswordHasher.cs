using System.Security.Cryptography;

namespace CistaNAS.Web.Crypto;

/// <summary>
/// ログインパスワードのハッシュ化・検証（PBKDF2-SHA256）。
/// 低レベル実装。Services（AuthService）から呼ばれる。
/// </summary>
/// <remarks>
/// 保存フォーマット: <c>pbkdf2-sha256$&lt;iterations&gt;$&lt;saltBase64&gt;$&lt;hashBase64&gt;</c>
/// </remarks>
public static class PasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const string Prefix = "pbkdf2-sha256";
    /// <summary>検証時の反復数上限（保存済みハッシュの改ざんによる CPU DoS を防ぐ）。</summary>
    private const int MaxVerifyIterations = 10_000_000;

    public static string Hash(string password, int iterations)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        // Verify 側の上限（MaxVerifyIterations）と一致させる。設定ミスで上限超のハッシュを
        // 生成すると Verify で弾かれてログイン不能になるため、生成時点でも拒否する。
        if (iterations < 1 || iterations > MaxVerifyIterations)
            throw new ArgumentOutOfRangeException(nameof(iterations), $"反復数は 1〜{MaxVerifyIterations} の範囲である必要があります。");

        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, HashSize);
        return $"{Prefix}${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    /// <summary>定数時間でパスワードを検証する。</summary>
    public static bool Verify(string password, string encoded)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(encoded)) return false;

        string[] parts = encoded.Split('$');
        if (parts.Length != 4 || parts[0] != Prefix) return false;
        if (!int.TryParse(parts[1], out int iterations) || iterations < 1 || iterations > MaxVerifyIterations) return false;

        byte[] salt, expected;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        byte[] actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
