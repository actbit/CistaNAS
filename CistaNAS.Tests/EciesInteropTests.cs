using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// ECIES (ECDH + HKDF + AES-256-GCM) のテスト。
/// WASM/Web の e2ee.js とプロトコル互換（raw 公開鍵 + HKDF-SHA256(salt=空, info="CistaNAS-ECIES")）。
/// </summary>
public class EciesInteropTests
{
    [Fact]
    public void GenerateEcdhKeyPair_PublicKey_Is65BytesRawUncompressed()
    {
        var (pubKey, _) = E2eeCrypto.GenerateEcdhKeyPair();

        Assert.Equal(65, pubKey.Length);
        Assert.Equal(0x04, pubKey[0]); // 非圧縮点: 0x04 || X[32] || Y[32]
    }

    [Fact]
    public void GenerateEcdhKeyPair_PrivateKey_IsSec1Importable()
    {
        var (_, privKey) = E2eeCrypto.GenerateEcdhKeyPair();

        // SEC1 秘密鍵として再インポート可能（ラウンドトリップ）
        using var ecdh = ECDiffieHellman.Create();
        ecdh.ImportECPrivateKey(privKey, out _);
        Assert.NotNull(ecdh);
    }

    [Fact]
    public void EcdhWrap_EphemeralPublicKey_Is65BytesRawUncompressed()
    {
        var (recipientPub, _) = E2eeCrypto.GenerateEcdhKeyPair();
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();

        var (ephPub, _, _, _) = E2eeCrypto.EcdhWrap(masterKey, recipientPub);

        Assert.Equal(65, ephPub.Length);
        Assert.Equal(0x04, ephPub[0]);
    }

    [Fact]
    public void EcdhWrapUnwrap_Roundtrips_MasterKey()
    {
        // 受信者（被共有者）の鍵ペア
        var (recipientPub, recipientPriv) = E2eeCrypto.GenerateEcdhKeyPair();
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();

        // 送信者が受信者の公開鍵でラップ
        var (ephPub, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, recipientPub);

        // 受信者が自分の秘密鍵でアンラップ
        byte[] recovered = E2eeCrypto.EcdhUnwrap(nonce, ct, tag, ephPub, recipientPriv);

        Assert.Equal(masterKey, recovered);
    }

    [Fact]
    public void EcdhWrapUnwrap_Roundtrips_AcrossTwoPairs()
    {
        // 異なる被共有者間で独立して成立すること（鍵ペアの混同がないか）
        var (pub1, priv1) = E2eeCrypto.GenerateEcdhKeyPair();
        var (pub2, priv2) = E2eeCrypto.GenerateEcdhKeyPair();
        byte[] mk1 = E2eeCrypto.GenerateMasterKey();
        byte[] mk2 = E2eeCrypto.GenerateMasterKey();

        var (eph1, n1, c1, t1) = E2eeCrypto.EcdhWrap(mk1, pub1);
        var (eph2, n2, c2, t2) = E2eeCrypto.EcdhWrap(mk2, pub2);

        Assert.Equal(mk1, E2eeCrypto.EcdhUnwrap(n1, c1, t1, eph1, priv1));
        Assert.Equal(mk2, E2eeCrypto.EcdhUnwrap(n2, c2, t2, eph2, priv2));

        // 交差しては復号できない
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeCrypto.EcdhUnwrap(n1, c1, t1, eph1, priv2));
    }

    [Fact]
    public void EcdhUnwrap_WrongPrivateKey_Throws()
    {
        var (recipientPub, _) = E2eeCrypto.GenerateEcdhKeyPair();
        var (_, otherPriv) = E2eeCrypto.GenerateEcdhKeyPair();
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();

        var (ephPub, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, recipientPub);

        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeCrypto.EcdhUnwrap(nonce, ct, tag, ephPub, otherPriv));
    }

    [Fact]
    public void EcdhUnwrap_TamperedCiphertext_Throws()
    {
        var (recipientPub, recipientPriv) = E2eeCrypto.GenerateEcdhKeyPair();
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();

        var (ephPub, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, recipientPub);
        ct[0] ^= 0xFF; // 改ざん

        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeCrypto.EcdhUnwrap(nonce, ct, tag, ephPub, recipientPriv));
    }

    /// <summary>
    /// DeriveRawSecretAgreement が生の ECDH 共有秘密 Z を返し、
    /// ECDH の可換性（A.priv+B.pub == B.priv+A.pub）を満たすことを確認。
    /// これはブラウザ crypto.subtle.deriveBits("ECDH", 256) と同じ生 Z を得ることの前提。
    /// </summary>
    [Fact]
    public void DeriveRawSecretAgreement_IsCommutative_And32Bytes()
    {
        using var a = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var b = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        byte[] ab = a.DeriveRawSecretAgreement(b.PublicKey);
        byte[] ba = b.DeriveRawSecretAgreement(a.PublicKey);

        Assert.Equal(32, ab.Length); // P-256 の X 座標
        Assert.Equal(ab, ba);
    }

    /// <summary>
    /// raw 公開鍵を文字列ハンドル経由で扱う実環境を模倣:
    /// ECParameters から手動で raw 65B を構築し、E2eeCrypto でラップ→アンラップ。
    /// </summary>
    [Fact]
    public void EcdhWrap_ManuallyConstructedRawPublicKey_Roundtrips()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var p = ecdh.ExportParameters(false);
        byte[] raw = new byte[65];
        raw[0] = 0x04;
        Buffer.BlockCopy(p.Q.X!, 0, raw, 1, 32);
        Buffer.BlockCopy(p.Q.Y!, 0, raw, 33, 32);
        byte[] priv = ecdh.ExportECPrivateKey();

        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        var (ephPub, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, raw);
        byte[] recovered = E2eeCrypto.EcdhUnwrap(nonce, ct, tag, ephPub, priv);

        Assert.Equal(masterKey, recovered);
    }

    [Fact]
    public void EcdhWrap_InvalidPublicKey_Throws()
    {
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] tooShort = new byte[64]; // 65 バイトでない

        Assert.Throws<ArgumentException>(() => E2eeCrypto.EcdhWrap(masterKey, tooShort));
    }
}
