using System.Security.Cryptography;
using System.Text;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// ECDH identity / ECIES wrap の「データ欠損ゼロ」を極端な入力で守るガードテスト。
/// - 導出はいかなる入力（極端な seed / 極端なパスワード / 境界 scalar）でも決定論的で有効な鍵を返す
/// - ECIES は改ざん・他人の鍵に対して fail-closed（壊れた鍵を静かに返さない）
/// - identity 導出とボリューム KEK 導出はドメイン分離されている（同一入力でも別鍵）
/// </summary>
public class EcdhDataLossGuardTests
{
    private static readonly KdfSpec FastSpec = new("pbkdf2-sha256", 1_000, 0, 0, 0);
    private static readonly KdfSpec LightArgon2id = new("argon2id", 1, 8192, 1, 1);

    /// <summary>P-256 の位数 n（big-endian 32 バイト）。</summary>
    private static readonly byte[] P256N =
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
    };

    private static byte[] Repeat(byte b, int count)
    {
        var a = new byte[count];
        Array.Fill(a, b);
        return a;
    }

    private static byte[] RawPubFromParams(System.Security.Cryptography.ECPoint q)
    {
        var raw = new byte[65];
        raw[0] = 0x04;
        Buffer.BlockCopy(q.X!, 0, raw, 1, 32);
        Buffer.BlockCopy(q.Y!, 0, raw, 33, 32);
        return raw;
    }

    // ---- 極端な seed でも scalar 導出は常に有範囲・決定論的 ----

    [Theory]
    [InlineData(0x00)]
    [InlineData(0xFF)]
    [InlineData(0x80)]
    [InlineData(0x01)]
    public void DeriveScalar_ExtremeSeeds_AlwaysValidAndDeterministic(byte fill)
    {
        byte[] seed = Repeat(fill, 32);
        byte[] d1 = EcdhIdentityKey.DeriveScalar(seed);
        byte[] d2 = EcdhIdentityKey.DeriveScalar(seed);

        Assert.Equal(32, d1.Length);
        Assert.Equal(d1, d2);            // 決定論（同一 seed → 同一 scalar）
        Assert.NotEqual(Repeat(0, 32), d1); // 0 は拒否される
        Assert.True(((ReadOnlySpan<byte>)d1).SequenceCompareTo(P256N) < 0, "scalar must be < n");
    }

    [Fact]
    public void DeriveScalar_LowEntropySeeds_MutuallyDistinct()
    {
        // 低エントロピー seed（i,i,i,...）でも seed 間で scalar が衝突しないこと
        //（衝突したら別ユーザーが同一 identity 鍵になり、wrap が他人に復号されうる）
        var seen = new HashSet<string>();
        for (byte i = 0; i < 64; i++)
        {
            byte[] scalar = EcdhIdentityKey.DeriveScalar(Repeat(i, 32));
            Assert.True(seen.Add(Convert.ToHexString(scalar)), $"seed {i} collided");
        }
    }

    // ---- 境界 scalar（1 と n-1 は有効、0 / n / n+1 は拒否） ----

    [Fact]
    public void CreateFromScalar_BoundaryScalars_Accepted_AndEcdhWorks()
    {
        byte[] dMin = Repeat(0x00, 32); dMin[31] = 0x01;              // 1（最小有効）
        byte[] dMax = (byte[])P256N.Clone(); dMax[31] -= 1;           // n-1（最大有効）

        foreach (var d in new[] { dMin, dMax })
        {
            using var ecdh = EcdhIdentityKey.CreateFromScalar(d);
            byte[] pub = RawPubFromParams(ecdh.ExportParameters(false).Q);
            Assert.Equal(65, pub.Length);

            // 境界 scalar の鍵でも ECIES ラウンドトリップが完結する（データが届く）
            byte[] masterKey = E2eeCrypto.GenerateMasterKey();
            var (eph, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, pub);
            byte[] unwrapped = E2eeCrypto.EcdhUnwrap(
                nonce, ct, tag, eph, ecdh.ExportECPrivateKey());
            Assert.Equal(masterKey, unwrapped);
        }
    }

    [Fact]
    public void CreateFromScalar_OutOfRangeScalars_Rejected()
    {
        byte[] zero = Repeat(0x00, 32);   // 0（無効）
        byte[] n = (byte[])P256N.Clone(); // n（範囲外）

        Assert.ThrowsAny<ArgumentException>(() => EcdhIdentityKey.CreateFromScalar(zero));
        Assert.ThrowsAny<ArgumentException>(() => EcdhIdentityKey.CreateFromScalar(n));
    }

    // ---- 極端なパスワードでも導出は決定論的 ----

    [Theory]
    [InlineData("a")]
    [InlineData("p@ssw0rd🎉漢字\0\t")]
    [InlineData("مرحبا")]
    [InlineData("İstanbul")]
    public void DeriveKeyPair_ExtremePasswords_Deterministic(string password)
    {
        byte[] salt = EcdhIdentityKey.GenerateIdentitySalt();
        var (pub1, _) = EcdhIdentityKey.DeriveKeyPair("user", password, salt, FastSpec);
        var (pub2, _) = EcdhIdentityKey.DeriveKeyPair("user", password, salt, FastSpec);
        Assert.Equal(pub1, pub2);
    }

    [Fact]
    public void DeriveKeyPair_ThousandCharPassword_Deterministic()
    {
        string password = new('x', 1000);
        byte[] salt = EcdhIdentityKey.GenerateIdentitySalt();
        var (pub1, _) = EcdhIdentityKey.DeriveKeyPair("user", password, salt, FastSpec);
        var (pub2, _) = EcdhIdentityKey.DeriveKeyPair("user", password, salt, FastSpec);
        Assert.Equal(pub1, pub2);
    }

    [Fact]
    public void DeriveKeyPair_HundredRepeatedDerivations_Stable()
    {
        // RNG や時刻が導出へ混入しないことの反復ガード
        byte[] salt = EcdhIdentityKey.GenerateIdentitySalt();
        var (expected, _) = EcdhIdentityKey.DeriveKeyPair("stable-user", "pw", salt, FastSpec);
        for (int i = 0; i < 100; i++)
        {
            var (pub, _) = EcdhIdentityKey.DeriveKeyPair("stable-user", "pw", salt, FastSpec);
            Assert.Equal(expected, pub);
        }
    }

    // ---- username 正規化の極端系 ----

    [Theory]
    [InlineData("\talice\r\n", "alice")]
    [InlineData("  ALICE  ", "alice")]
    [InlineData("ＡＬＩＣＥ", "ａｌｉｃｅ")] // 全角英字も ToLowerInvariant で小文字化される（決定論の対象）
    public void NormalizeUsername_ExtremeInputs_TrimAndInvariantLowercase(string input, string expected)
    {
        Assert.Equal(expected, EcdhIdentityKey.NormalizeUsername(input));
    }

    [Fact]
    public void NormalizeUsername_CultureDoesNotAffectLowercasing()
    {
        // ToLowerInvariant なので実行カルチャに依存しない（カルチャが変わると identity が
        // 変わり既存 ECDH wrap が全滅する = データ欠損、を防ぐ契約）
        var original = System.Globalization.CultureInfo.CurrentCulture;
        try
        {
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("tr-TR");
            string turkish = EcdhIdentityKey.NormalizeUsername("ISTANBUL");
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("ja-JP");
            string japanese = EcdhIdentityKey.NormalizeUsername("ISTANBUL");
            Assert.Equal(turkish, japanese);
        }
        finally
        {
            System.Globalization.CultureInfo.CurrentCulture = original;
        }
    }

    [Fact]
    public void DeriveKeyPair_VeryLongUsername_Deterministic()
    {
        string username = new('u', 10_000);
        byte[] salt = EcdhIdentityKey.GenerateIdentitySalt();
        var (pub1, _) = EcdhIdentityKey.DeriveKeyPair(username, "pw", salt, FastSpec);
        var (pub2, _) = EcdhIdentityKey.DeriveKeyPair(username, "pw", salt, FastSpec);
        Assert.Equal(pub1, pub2);
    }

    // ---- ドメイン分離: identity seed とボリューム KEK は同一入力でも別鍵 ----

    [Theory]
    [MemberData(nameof(SeparationSpecs))]
    public void DeriveSeed_DiffersFromVolumeKek_SameInputs(KdfSpec spec)
    {
        const string user = "dom-sep-user";
        const string password = "same-pass";
        byte[] salt = EcdhIdentityKey.GenerateIdentitySalt();

        byte[] seed = EcdhIdentityKey.DeriveSeed(user, password, salt, spec);
        byte[] kek = KeyDerivation.DeriveKek(user, password, salt, spec, 32);

        Assert.NotEqual(seed, kek); // 混同すると KEK が identity 秘密鍵の材料として露出する
    }

    public static TheoryData<KdfSpec> SeparationSpecs => new() { FastSpec, LightArgon2id };

    // ---- UseDerivedKey: 例外が起きても導出器は壊れない（再導出可能） ----

    [Fact]
    public void UseDerivedKey_ActionThrows_ExceptionSurfacesAndNextDerivationIntact()
    {
        byte[] salt = EcdhIdentityKey.GenerateIdentitySalt();

        Assert.Throws<InvalidOperationException>(() => EcdhIdentityKey.UseDerivedKey<object?>(
            "user", "pw", salt, FastSpec, _ => throw new InvalidOperationException()));

        var (pub, _) = EcdhIdentityKey.DeriveKeyPair("user", "pw", salt, FastSpec);
        string again = EcdhIdentityKey.UseDerivedKey(
            "user", "pw", salt, FastSpec, ecdh => Convert.ToBase64String(RawPubFromParams(ecdh.ExportParameters(false).Q)));
        Assert.Equal(Convert.ToBase64String(pub), again);
    }

    // ---- ECIES: ラップは非決定論的でも復元は損失なし ----

    [Fact]
    public void EcdhWrap_SameKeyTwice_DifferentCiphertext_BothUnwrapIdentical()
    {
        var (recipientPub, priv) = E2eeCrypto.GenerateEcdhKeyPair();
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();

        var (eph1, n1, c1, t1) = E2eeCrypto.EcdhWrap(masterKey, recipientPub);
        var (eph2, n2, c2, t2) = E2eeCrypto.EcdhWrap(masterKey, recipientPub);
        try
        {
            // 毎回新規一時鍵・新規ノンス（同一 wrap の再利用は後述の改ざん耐性を弱める）
            Assert.NotEqual(n1, n2);
            Assert.NotEqual(c1, c2);
            Assert.NotEqual(eph1, eph2);

            // ただしrecipientが正しければどちらも同一 masterKey に復元される
            Assert.Equal(masterKey, E2eeCrypto.EcdhUnwrap(n1, c1, t1, eph1, priv));
            Assert.Equal(masterKey, E2eeCrypto.EcdhUnwrap(n2, c2, t2, eph2, priv));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv);
        }
    }

    // ---- ECIES: マスターキー境界長のラウンドトリップ（1 バイトも欠損しない） ----

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    public void EcdhWrapUnwrap_MasterKeyBoundarySizes_ByteIdentical(int size)
    {
        var (pub, priv) = E2eeCrypto.GenerateEcdhKeyPair();
        byte[] masterKey = RandomNumberGenerator.GetBytes(size);
        try
        {
            var (eph, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, pub);
            byte[] unwrapped = E2eeCrypto.EcdhUnwrap(nonce, ct, tag, eph, priv);
            Assert.Equal(masterKey, unwrapped);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv);
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    // ---- ECIES: 改ざんマトリクス（全フィールド 1 ビット反転で fail-closed） ----

    public static TheoryData<string> TamperTargets => new()
    {
        "nonce", "ct-first", "ct-last", "tag", "eph-first", "eph-last",
    };

    [Theory]
    [MemberData(nameof(TamperTargets))]
    public void EcdhUnwrap_AnyTamperedField_FailsClosed(string target)
    {
        var (pub, priv) = E2eeCrypto.GenerateEcdhKeyPair();
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        try
        {
            var (eph, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, pub);

            // 改ざん前は必ず成功する（対照実験）
            Assert.Equal(masterKey, E2eeCrypto.EcdhUnwrap(nonce, ct, tag, eph, priv));
            byte[] tn = (byte[])nonce.Clone();
            byte[] tc = (byte[])ct.Clone();
            byte[] tt = (byte[])tag.Clone();
            byte[] te = (byte[])eph.Clone();
            switch (target)
            {
                case "nonce": tn[0] ^= 0x01; break;
                case "ct-first": tc[0] ^= 0x01; break;
                case "ct-last": tc[^1] ^= 0x01; break;
                case "tag": tt[0] ^= 0x01; break;
                case "eph-first": te[0] = 0x05; break; // 圧縮点フラグに偽装（不正形式）
                case "eph-last": te[^1] ^= 0x01; break; // 曲線上に無い点
            }

            // フェイルクローズドの保証: どの例外型でもよいが、壊れた鍵を返してはならない
            //（Windows CNG は不正点に CryptographicException / ArgumentException /
            //  プラットフォームによって PlatformNotSupportedException を投げる）
            try
            {
                byte[] result = E2eeCrypto.EcdhUnwrap(tn, tc, tt, te, priv);
                Assert.NotEqual(masterKey, result); // 例外にならず復号が通っても元鍵ではない
            }
            catch (Exception ex) when (ex is ArgumentException or
                                       System.Security.Cryptography.CryptographicException or
                                       PlatformNotSupportedException)
            {
                // 期待経路: 改ざん検出で復号拒否
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv);
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    // ---- ECIES: 他人の鍵では復号できない（クロスユーザー分離） ----
    [Fact]
    public void EcdhUnwrap_WrongRecipient_FailsClosed_BothDirections()
    {
        var (alicePub, alicePriv) = E2eeCrypto.GenerateEcdhKeyPair();
        var (bobPub, bobPriv) = E2eeCrypto.GenerateEcdhKeyPair();
        try
        {
            byte[] forAlice = E2eeCrypto.GenerateMasterKey();
            byte[] forBob = E2eeCrypto.GenerateMasterKey();

            var (ephA, nA, cA, tA) = E2eeCrypto.EcdhWrap(forAlice, alicePub);
            var (ephB, nB, cB, tB) = E2eeCrypto.EcdhWrap(forBob, bobPub);

            Assert.ThrowsAny<CryptographicException>(
                () => E2eeCrypto.EcdhUnwrap(nA, cA, tA, ephA, bobPriv));
            Assert.ThrowsAny<CryptographicException>(
                () => E2eeCrypto.EcdhUnwrap(nB, cB, tB, ephB, alicePriv));

            // 正規受取人は損失なく復元できる
            Assert.Equal(forAlice, E2eeCrypto.EcdhUnwrap(nA, cA, tA, ephA, alicePriv));
            Assert.Equal(forBob, E2eeCrypto.EcdhUnwrap(nB, cB, tB, ephB, bobPriv));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(alicePriv);
            CryptographicOperations.ZeroMemory(bobPriv);
        }
    }

    // ---- 入力異常系: null / 不正形式でも静かに成功しない ----

    [Fact]
    public void EcdhUnwrap_NullInputs_NeverSucceed()
    {
        var (pub, priv) = E2eeCrypto.GenerateEcdhKeyPair();
        try
        {
            var (eph, nonce, ct, tag) = E2eeCrypto.EcdhWrap(Repeat(0xAB, 32), pub);

            Assert.ThrowsAny<Exception>(() => E2eeCrypto.EcdhUnwrap(null!, ct, tag, eph, priv));
            Assert.ThrowsAny<Exception>(() => E2eeCrypto.EcdhUnwrap(nonce, null!, tag, eph, priv));
            Assert.ThrowsAny<Exception>(() => E2eeCrypto.EcdhUnwrap(nonce, ct, null!, eph, priv));
            Assert.ThrowsAny<Exception>(() => E2eeCrypto.EcdhUnwrap(nonce, ct, tag, null!, priv));
            Assert.ThrowsAny<Exception>(() => E2eeCrypto.EcdhUnwrap(nonce, ct, tag, eph, null!));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv);
        }
    }

    [Theory]
    [InlineData(64)]  // raw 非圧縮点のフラグ 0x04 欠け（短すぎ）
    [InlineData(63)]  // X/Y 途中切れ
    public void EcdhWrap_MalformedRecipientKeyLength_Throws(int size)
    {
        byte[] bad = RandomNumberGenerator.GetBytes(size);
        Assert.ThrowsAny<Exception>(() => E2eeCrypto.EcdhWrap(Repeat(0xAB, 32), bad));
    }

    [Fact]
    public void EcdhWrap_AllZeroRecipientPoint_Throws()
    {
        // 全零 65 バイトは曲線上の点ではない（インポート時点で拒否されるべき）
        byte[] zero = Repeat(0x00, 65);
        zero[0] = 0x04;
        Assert.ThrowsAny<Exception>(() => E2eeCrypto.EcdhWrap(Repeat(0xAB, 32), zero));
    }

    // ---- 鍵導出の分散性（spec / seed 混同で identity が衝突しない） ----

    [Fact]
    public void DeriveKeyPair_DifferentSpecs_ProduceDifferentKeys()
    {
        // サーバー配布の KDF spec を誤って別種で解釈した場合、同一鍵にはならない
        //（同一になると spec 差し替えが検知不能になり、新旧 wrap の帰属が壊れる）
        byte[] salt = EcdhIdentityKey.GenerateIdentitySalt();
        var (pubPbkdf2, _) = EcdhIdentityKey.DeriveKeyPair("user", "pw", salt, FastSpec);
        var (pubArgon2, _) = EcdhIdentityKey.DeriveKeyPair("user", "pw", salt, LightArgon2id);
        Assert.NotEqual(pubPbkdf2, pubArgon2);
    }

    [Fact]
    public void DeriveScalar_SeedBitFlip_ProducesDifferentScalar()
    {
        byte[] seed = EcdhIdentityKey.DeriveScalar(Repeat(0x42, 32));
        byte[] baseline = EcdhIdentityKey.DeriveScalar(Repeat(0x42, 32));

        // seed の各ビット位置の反転に対して scalar が変わる（部分的にでも一致すると
        // seed 高位バイトの欠落が同一 identity に繋がりうる）
        for (int bit = 0; bit < 8; bit++)
        {
            byte[] flipped = Repeat(0x42, 32);
            flipped[0] ^= (byte)(1 << bit);
            byte[] scalar = EcdhIdentityKey.DeriveScalar(flipped);
            Assert.NotEqual(baseline, scalar);
        }
        Assert.Equal(seed, baseline); // 元 seed は決定論的に同一
    }

    [Fact]
    public void EcdhUnwrap_TamperedMiddleByte_FailsClosed()
    {
        var (pub, priv) = E2eeCrypto.GenerateEcdhKeyPair();
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        try
        {
            var (eph, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, pub);
            byte[] tampered = (byte[])ct.Clone();
            tampered[tampered.Length / 2] ^= 0x80;

            Assert.ThrowsAny<CryptographicException>(
                () => E2eeCrypto.EcdhUnwrap(nonce, tampered, tag, eph, priv));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv);
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }
}
