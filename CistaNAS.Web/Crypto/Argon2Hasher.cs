using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Web.Crypto;

/// <summary>
/// ログインパスワードの Argon2id ハッシュ（PHC 文字列形式）。
/// 低レベル実装。<see cref="Identity.Argon2PasswordHasher"/> から呼ばれる。
/// </summary>
/// <remarks>
/// 保存フォーマット（PHC 標準、salt/hash は base64url 無パディング）:
/// <c>$argon2id$v=19$m=&lt;KiB&gt;,t=&lt;time&gt;,p=&lt;lanes&gt;$&lt;saltB64url&gt;$&lt;hashB64url&gt;</c>
/// </remarks>
public static class Argon2Hasher
{
    /// <summary>同時実行できる Argon2id 計算数の上限。ログイン洪水中のメモリ枯渇
    /// （1 計算 = 既定 64 MiB）を防ぐためのグローバルゲート。</summary>
    private static readonly SemaphoreSlim KdfGate = new(8, 8);

    /// <summary>PHC 形式の接頭辞。</summary>
    public const string Prefix = "$argon2id$";

    /// <summary>ダミー計算（ユーザー列挙タイミング均一化）用の軽量プロファイル。
    /// 未認証リクエストで本番相当のメモリを奪わせないため軽量にする。</summary>
    private const int DummyMemoryKiB = 16384;   // 16 MiB
    private const int DummyTimeCost = 2;
    private const int DummyParallelism = 1;

    /// <summary>Argon2id ハッシュを生成する（パラメータは現行設定）。</summary>
    public static string Hash(string password, int timeCost, int memoryKiB, int parallelism)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        Argon2idKdf.ValidateParams(timeCost, memoryKiB, parallelism);

        byte[] salt = RandomNumberGenerator.GetBytes(16);
        KdfGate.Wait();
        try
        {
            byte[] hash = Argon2idKdf.Derive(password, salt, timeCost, memoryKiB, parallelism, 32);
            return $"$argon2id$v={Argon2idKdf.Version}$m={memoryKiB},t={timeCost},p={parallelism}" +
                   $"${ToPhcBase64(salt)}${ToPhcBase64(hash)}";
        }
        finally
        {
            KdfGate.Release();
        }
    }

    /// <summary>
    /// PHC 形式の Argon2id ハッシュを検証する。
    /// 保存済みパラメータは上限チェックし、改ざんによるメモリ/CPU DoS を防ぐ。
    /// </summary>
    public static bool Verify(string password, string encoded)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(encoded)) return false;
        if (!encoded.StartsWith(Prefix, StringComparison.Ordinal)) return false;

        // $argon2id$v=19$m=65536,t=4,p=4$salt$hash → ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
        string[] parts = encoded.Split('$');
        if (parts.Length != 6 || parts[1] != "argon2id") return false;
        if (parts[2] != $"v={Argon2idKdf.Version}") return false;

        int memoryKiB = 0, timeCost = 0, parallelism = 0;
        foreach (string seg in parts[3].Split(','))
        {
            int eq = seg.IndexOf('=');
            if (eq < 1) return false;
            string key = seg[..eq];
            if (!int.TryParse(seg[(eq + 1)..], out int value)) return false;
            switch (key)
            {
                case "m": memoryKiB = value; break;
                case "t": timeCost = value; break;
                case "p": parallelism = value; break;
                default: return false;
            }
        }

        if (!Argon2idKdf.IsWithinVerifyLimits(timeCost, memoryKiB, parallelism)) return false;

        byte[] salt, expected;
        try
        {
            salt = FromPhcBase64(parts[4]);
            expected = FromPhcBase64(parts[5]);
        }
        catch (FormatException)
        {
            return false;
        }
        if (salt.Length < 8 || expected.Length < 16) return false;

        KdfGate.Wait();
        try
        {
            byte[] actual = Argon2idKdf.Derive(password, salt, timeCost, memoryKiB, parallelism, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        finally
        {
            KdfGate.Release();
        }
    }

    /// <summary>
    /// ユーザー不在時のダミー Argon2id 計算（タイミング均一化）。
    /// 軽量プロファイル + ゲートで、未認証リクエストからのメモリ/CPU DoS を抑える。
    /// </summary>
    public static void RunDummy()
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        KdfGate.Wait();
        try
        {
            Argon2idKdf.Derive("dummy", salt, DummyTimeCost, DummyMemoryKiB, DummyParallelism, 32);
        }
        finally
        {
            KdfGate.Release();
        }
    }

    /// <summary>PHC base64url（無パディング）エンコード。</summary>
    public static string ToPhcBase64(byte[] data)
    {
        string s = Convert.ToBase64String(data);
        return s.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>PHC base64url（無パディング）デコード。</summary>
    public static byte[] FromPhcBase64(string s)
    {
        // 置換: '-'→'+', '_'→'/'、パディング復元
        string padded = s.Replace('-', '+').Replace('_', '/');
        int rem = padded.Length % 4;
        if (rem > 0) padded += new string('=', 4 - rem);
        return Convert.FromBase64String(padded);
    }
}
