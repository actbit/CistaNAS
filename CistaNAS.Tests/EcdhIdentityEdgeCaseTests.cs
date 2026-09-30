using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// 決定論的 ECDH identity 鍵導出のエッジケーステスト（データ欠損・誤導出の防止）。
/// - 入力バリデーション（空 / 空白のみ / 境界 salt サイズ / 空 password）
/// - Unicode ユーザー名の正規化不変性（前後空白・大文字小文字で同一鍵）
/// - 異常系 scalar の拒否（zeroize 済みデータや不正長での誤復号を防ぐ）
/// - SEC1 往復で公開鍵が不変（鍵情報の欠損がないこと）
/// </summary>
public class EcdhIdentityEdgeCaseTests
{
    private static readonly byte[] FixedSalt = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly KdfSpec TestSpec = new("argon2id", 1000, 8192, 2, 1);
    private const string P256OrderHex =
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    private static byte[] Hex(string s) => Convert.FromHexString(s);

    // ---- 入力バリデーション ----

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n ")]
    public void NormalizeUsername_EmptyOrWhitespace_Throws(string username)
    {
        // 空ユーザー名からの導出は salt 単体の KDF に退行するため fail-fast する
        Assert.ThrowsAny<ArgumentException>(() => EcdhIdentityKey.NormalizeUsername(username));
    }

    [Fact]
    public void Derive_EmptyUsername_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(
            () => EcdhIdentityKey.DeriveKeyPair("", "pw", FixedSalt, TestSpec));
    }

    [Fact]
    public void Derive_WhitespaceOnlyUsername_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(
            () => EcdhIdentityKey.DeriveKeyPair("   ", "pw", FixedSalt, TestSpec));
    }

    [Fact]
    public void Derive_EmptyPassword_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(
            () => EcdhIdentityKey.DeriveKeyPair("alice", "", FixedSalt, TestSpec));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(7)]
    public void Derive_SaltTooSmall_Throws(int saltSize)
    {
        byte[] salt = new byte[saltSize];
        Assert.ThrowsAny<ArgumentException>(
            () => EcdhIdentityKey.DeriveKeyPair("alice", "pw", salt, TestSpec));
    }

    [Theory]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(64)]
    [InlineData(1024)]
    public void Derive_SaltBoundarySizes_Accepted_AndDeterministic(int saltSize)
    {
        byte[] salt = Enumerable.Range(0, saltSize).Select(i => (byte)(i * 7)).ToArray();
        var (pub1, priv1) = EcdhIdentityKey.DeriveKeyPair("alice", "pw", salt, TestSpec);
        var (pub2, priv2) = EcdhIdentityKey.DeriveKeyPair("alice", "pw", salt, TestSpec);
        try
        {
            Assert.Equal(pub1, pub2);
            Assert.Equal(priv1, priv2);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv1);
            CryptographicOperations.ZeroMemory(priv2);
        }
    }

    [Fact]
    public void Derive_SaltTooLarge_Throws()
    {
        byte[] salt = new byte[1025];
        Assert.ThrowsAny<ArgumentException>(
            () => EcdhIdentityKey.DeriveKeyPair("alice", "pw", salt, TestSpec));
    }

    [Fact]
    public void Derive_NullSalt_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(
            () => EcdhIdentityKey.DeriveKeyPair("alice", "pw", null!, TestSpec));
    }

    // ---- Unicode / 長大入力の正規化不変性 ----

    [Fact]
    public void Derive_UnicodeUsername_NormalizationInvariant()
    {
        // アクセント付きラテン: Trim + ToLowerInvariant のみで正規化される
        var (basePub, _) = EcdhIdentityKey.DeriveKeyPair("Ünïcødé-Üser", "pw", FixedSalt, TestSpec);
        var (variantPub, variantPriv) = EcdhIdentityKey.DeriveKeyPair("  ÜNÏCØDÉ-ÜSER ", "pw", FixedSalt, TestSpec);
        CryptographicOperations.ZeroMemory(variantPriv);
        Assert.Equal(basePub, variantPub);
    }

    [Fact]
    public void Derive_LongUsername_Deterministic()
    {
        string longName = new string('u', 1000) + "-1";
        var (pub1, priv1) = EcdhIdentityKey.DeriveKeyPair(longName, "pw", FixedSalt, TestSpec);
        var (pub2, priv2) = EcdhIdentityKey.DeriveKeyPair(longName, "pw", FixedSalt, TestSpec);
        try
        {
            Assert.Equal(pub1, pub2);
            Assert.Equal(priv1, priv2);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv1);
            CryptographicOperations.ZeroMemory(priv2);
        }
    }

    [Theory]
    [InlineData("p@ss w0rd!🎉 漢字")]
    [InlineData("x")]
    [InlineData("very-long-" + "password" + "0123456789012345678901234567890123456789")]
    public void Derive_SpecialPasswords_Deterministic(string password)
    {
        var (pub1, priv1) = EcdhIdentityKey.DeriveKeyPair("alice", password, FixedSalt, TestSpec);
        var (pub2, priv2) = EcdhIdentityKey.DeriveKeyPair("alice", password, FixedSalt, TestSpec);
        try
        {
            Assert.Equal(pub1, pub2);
            Assert.Equal(priv1, priv2);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv1);
            CryptographicOperations.ZeroMemory(priv2);
        }
    }

    // ---- KDF スペック差分 ----

    [Fact]
    public void Derive_Argon2idComposite_VsRaw_ProducesDifferentKeys()
    {
        // 合成 (Argon2id→PBKDF2) と raw (Argon2id 単独) は同パラメータでも別鍵
        var composite = new KdfSpec("argon2id", 1000, 8192, 1, 2);
        var raw = new KdfSpec("argon2id-raw", 0, 8192, 1, 2);
        var (pub1, _) = EcdhIdentityKey.DeriveKeyPair("alice", "pw", FixedSalt, composite);
        var (pub2, _) = EcdhIdentityKey.DeriveKeyPair("alice", "pw", FixedSalt, raw);
        Assert.NotEqual(pub1, pub2);
    }

    [Fact]
    public void Derive_VersionOverload_WrongVersion_Throws()
    {
        Assert.ThrowsAny<ArgumentOutOfRangeException>(
            () => EcdhIdentityKey.DeriveKeyPair("alice", "pw", FixedSalt, version: 99));
    }

    // ---- scalar / 鍵構築の異常系 ----

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(0)]
    public void DeriveScalar_WrongLength_Throws(int length)
    {
        byte[] seed = RandomNumberGenerator.GetBytes(32);
        try
        {
            Assert.ThrowsAny<ArgumentException>(() => EcdhIdentityKey.DeriveScalar(new byte[length]));
            Assert.ThrowsAny<ArgumentException>(() => EcdhIdentityKey.DeriveScalar(null!));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    [Fact]
    public void CreateFromScalar_InvalidScalars_Rejected()
    {
        // 0, n, n+1, 全 0xFF は有効な P-256 scalar ではない → 誤復号の温床になるため拒否
        Assert.ThrowsAny<ArgumentException>(() => EcdhIdentityKey.CreateFromScalar(new byte[32]));

        byte[] order = Hex(P256OrderHex);
        Assert.ThrowsAny<ArgumentException>(() => EcdhIdentityKey.CreateFromScalar((byte[])order.Clone()));

        byte[] orderPlusOne = Hex(P256OrderHex);
        orderPlusOne[31]++;
        Assert.ThrowsAny<ArgumentException>(() => EcdhIdentityKey.CreateFromScalar(orderPlusOne));

        byte[] allFF = Enumerable.Repeat((byte)0xFF, 32).ToArray();
        Assert.ThrowsAny<ArgumentException>(() => EcdhIdentityKey.CreateFromScalar(allFF));

        Assert.ThrowsAny<ArgumentException>(() => EcdhIdentityKey.CreateFromScalar(new byte[31]));
        Assert.ThrowsAny<ArgumentException>(() => EcdhIdentityKey.CreateFromScalar(new byte[33]));
    }

    // ---- 鍵情報の完全性（欠損なし） ----

    [Fact]
    public void DeriveKeyPair_Sec1Roundtrip_PreservesPublicKey()
    {
        // SEC1 秘密鍵を再 import しても公開鍵が 1 バイトも変わらないこと（鍵情報の欠損防止）
        var (pub, priv) = EcdhIdentityKey.DeriveKeyPair("alice", "pw", FixedSalt, TestSpec);
        try
        {
            using var ecdh = ECDiffieHellman.Create();
            ecdh.ImportECPrivateKey(priv, out _);
            byte[] republished = E2eeCrypto.ExportRawPublicKey(ecdh.ExportParameters(false).Q);
            Assert.Equal(pub, republished);
            Assert.Equal(65, pub.Length);
            Assert.Equal(0x04, pub[0]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv);
        }
    }

    [Fact]
    public void UseDerivedKey_SameKeyAsDeriveKeyPair()
    {
        var (pub, priv) = EcdhIdentityKey.DeriveKeyPair("alice", "pw", FixedSalt, TestSpec);
        try
        {
            byte[] pubViaCallback = EcdhIdentityKey.UseDerivedKey(
                "alice", "pw".AsSpan(), FixedSalt, TestSpec,
                ecdh => E2eeCrypto.ExportRawPublicKey(ecdh.ExportParameters(false).Q));
            Assert.Equal(pub, pubViaCallback);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv);
        }
    }

    [Fact]
    public void GenerateIdentitySalt_BoundaryLengths_AreAlways32()
    {
        for (int i = 0; i < 16; i++)
        {
            byte[] salt = EcdhIdentityKey.GenerateIdentitySalt();
            Assert.Equal(EcdhIdentityKey.IdentitySaltSize, salt.Length);
        }
    }
}
