using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace CistaNAS.Shared.Crypto;

/// <summary>
/// 決定論的 ECDH identity 鍵導出。
///
/// ECDH 秘密鍵はランダム生成してストレージへ保存するのではなく、
/// username / E2EE password / identity salt / derivation version から必要時に決定論的に導出する。
/// 秘密鍵は RAM 上のセッション中のみ存在し、永続化ストレージ（ファイル / localStorage /
/// secure store 等）へは一切書き込まない。サーバーには公開鍵と identity salt（非秘密）のみを保存する。
///
/// 導出仕様（全プラットフォーム .NET / browser e2ee.js で同一。テストベクトルで固定）:
/// 1. ikm   = KdfSpecApply(password, salt = identitySalt, spec, 32)   … ボリューム KEK と同一の KDF 入力規約
/// 2. seed  = HKDF-SHA256(ikm, salt = identitySalt,
///                        info = "CistaNAS-ECDH-Identity-v1" || normalizedUsername, 32)
/// 3. d     = P-256 scalar 導出: HMAC-SHA256(seed, "CistaNAS-P256-Scalar-v1" || le32(counter))
///            を 1 &lt;= d &lt; n（n = P-256 の位数）を満たすまで rejection sampling（mod n は bias のため不使用）
/// 4. public key = raw 非圧縮点（0x04 || X || Y, 65 byte）、private key = SEC1
/// normalizedUsername は username.Trim().ToLowerInvariant()（culture 非依存）。
/// </summary>
public static class EcdhIdentityKey
{
    /// <summary>現行の導出バージョン。仕様変更時は +1 する。</summary>
    public const int CurrentDerivationVersion = 1;

    /// <summary>identity salt サイズ（バイト）。非秘密でサーバー DB に保存する。</summary>
    public const int IdentitySaltSize = 32;

    /// <summary>KDF 出力のドメイン分離コンテキスト。ボリューム KEK との混同を防ぐ。</summary>
    public const string KdfDomainContext = "CistaNAS-ECDH-Identity-v1";

    /// <summary>P-256 scalar 導出のドメイン分離コンテキスト。</summary>
    public const string ScalarDomainContext = "CistaNAS-P256-Scalar-v1";

    private static ReadOnlySpan<byte> P256Order => new byte[]
    {
        // n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 (big-endian)
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
    };

    /// <summary>identity salt を CSPRNG で生成する（32 バイト）。</summary>
    public static byte[] GenerateIdentitySalt() => RandomNumberGenerator.GetBytes(IdentitySaltSize);

    /// <summary>
    /// 鍵導出用に username を正規化する（Trim + culture 非依存 lowercase）。
    /// 全プラットフォームで同一の入力を保証するため、導出前に必ず通す。
    /// </summary>
    public static string NormalizeUsername(string username)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        return username.Trim().ToLowerInvariant();
    }

    /// <summary>
    /// identity seed（32 バイト）を導出する。seed は秘密情報であり、呼び出し側は使用後に
    /// <see cref="CryptographicOperations.ZeroMemory"/> で破棄すること。
    /// </summary>
    public static byte[] DeriveSeed(string username, ReadOnlySpan<char> password, byte[] identitySalt, KdfSpec spec)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentNullException.ThrowIfNull(identitySalt);
        if (identitySalt.Length is < 8 or > 1024)
            throw new ArgumentOutOfRangeException(nameof(identitySalt), "identity salt は 8〜1024 バイトである必要があります。");

        // 前段: ボリューム KEK と同じ KDF 入力規約（CombineUserSalt で username を salt に混入）で 32B を導出。
        // username は正規化してから渡す（大文字小文字・前後空白の違いで identity が変わらないようにする）
        byte[] ikm = KeyDerivation.DeriveKek(NormalizeUsername(username), password.ToString(), identitySalt, spec, 32);
        try
        {
            // 後段: HKDF で ECDH identity 用にドメイン分離（ボリューム KEK と同一バイトを流用しない）
            byte[] normalized = Encoding.UTF8.GetBytes(NormalizeUsername(username));
            byte[] context = Encoding.UTF8.GetBytes(KdfDomainContext);
            byte[] info = new byte[context.Length + normalized.Length];
            Buffer.BlockCopy(context, 0, info, 0, context.Length);
            Buffer.BlockCopy(normalized, 0, info, context.Length, normalized.Length);
            try
            {
                return E2eeCrypto.HkdfSha256(ikm, identitySalt, info, 32);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(info);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    /// <summary>
    /// seed から P-256 private scalar（32 バイト big-endian）を rejection sampling で導出する。
    /// HMAC-SHA256(seed, ScalarDomainContext || le32(counter)) を 1 &lt;= d &lt; n を満たすまで試す。
    /// 戻り値は秘密情報のため、呼び出し側は使用後に破棄すること。
    /// </summary>
    public static byte[] DeriveScalar(byte[] seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        if (seed.Length != 32)
            throw new ArgumentException("seed は 32 バイトである必要があります。", nameof(seed));

        byte[] infoPrefix = Encoding.UTF8.GetBytes(ScalarDomainContext);
        try
        {
            for (uint counter = 0; ; counter++)
            {
                byte[] input = new byte[infoPrefix.Length + 4];
                Buffer.BlockCopy(infoPrefix, 0, input, 0, infoPrefix.Length);
                BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(infoPrefix.Length), counter);
                byte[] candidate;
                using (var hmac = new HMACSHA256(seed))
                {
                    candidate = hmac.ComputeHash(input);
                }
                CryptographicOperations.ZeroMemory(input);
                if (IsValidScalar(candidate))
                    return candidate;
                CryptographicOperations.ZeroMemory(candidate);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(infoPrefix);
        }
    }

    /// <summary>big-endian 32 バイト scalar が 1 &lt;= d &lt; n を満たすか。</summary>
    private static bool IsValidScalar(ReadOnlySpan<byte> d)
    {
        bool allZero = true;
        foreach (byte b in d)
        {
            if (b != 0) { allZero = false; break; }
        }
        if (allZero) return false;
        return d.SequenceCompareTo(P256Order) < 0;
    }

    /// <summary>
    /// private scalar から ECDH P-256 インスタンスを構築する（公開鍵は BCL が計算する）。
    /// 戻り値は using で破棄すること。
    /// </summary>
    public static ECDiffieHellman CreateFromScalar(byte[] scalar)
    {
        ArgumentNullException.ThrowIfNull(scalar);
        if (scalar.Length != 32 || !IsValidScalar(scalar))
            throw new ArgumentException("scalar は 1 <= d < n の 32 バイトである必要があります。", nameof(scalar));
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = (byte[])scalar.Clone(),
        };
        return ECDiffieHellman.Create(parameters);
    }

    /// <summary>
    /// 決定論的に ECDH identity 鍵ペアを導出する。
    /// 戻り値の秘密鍵（SEC1）は秘密情報であり、使用後に必ず zeroize すること。
    /// 永続化ストレージへ書き込まないこと。
    /// </summary>
    public static (byte[] PublicKeyRaw, byte[] PrivateKeySec1) DeriveKeyPair(
        string username, ReadOnlySpan<char> password, byte[] identitySalt, KdfSpec spec)
    {
        byte[] seed = DeriveSeed(username, password, identitySalt, spec);
        try
        {
            byte[] scalar = DeriveScalar(seed);
            CryptographicOperations.ZeroMemory(seed);
            try
            {
                using var ecdh = CreateFromScalar(scalar);
                byte[] publicKey = E2eeCrypto.ExportRawPublicKey(ecdh.ExportParameters(false).Q);
                byte[] privateKeySec1 = ecdh.ExportECPrivateKey();
                return (publicKey, privateKeySec1);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(scalar);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    /// <summary>
    /// 決定論的に導出した ECDH 鍵を callback 内だけで使用する（秘密鍵の露出時間を最小化する推奨形）。
    /// callback には ECDiffieHellman インスタンスが渡され、戻り時に鍵は破棄・zeroize される。
    /// </summary>
    public static T UseDerivedKey<T>(
        string username, ReadOnlySpan<char> password, byte[] identitySalt, KdfSpec spec, Func<ECDiffieHellman, T> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        byte[] seed = DeriveSeed(username, password, identitySalt, spec);
        try
        {
            byte[] scalar = DeriveScalar(seed);
            CryptographicOperations.ZeroMemory(seed);
            try
            {
                using var ecdh = CreateFromScalar(scalar);
                CryptographicOperations.ZeroMemory(scalar);
                return action(ecdh);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(scalar);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    /// <summary>
    /// 既定スペック（Argon2id 合成、KdfSpec.DefaultArgon2id）で identity 鍵ペアを導出する。
    /// サーバー設定の E2EE KDF スペックを優先する場合は <see cref="DeriveKeyPair"/> の spec 引数版を使うこと。
    /// </summary>
    public static (byte[] PublicKeyRaw, byte[] PrivateKeySec1) DeriveKeyPair(
        string username, ReadOnlySpan<char> password, byte[] identitySalt, int version)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(version, CurrentDerivationVersion);
        return DeriveKeyPair(username, password, identitySalt, KdfSpec.DefaultArgon2id);
    }
}
