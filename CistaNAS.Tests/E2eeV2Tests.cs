using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// 共有 E2EE crypto format v2 (E2eeV2) の単体テスト:
/// GroupKey epoch ラップ / per-file DEK / 強化 AAD / チャンク暗号化 / TOFU fingerprint。
/// Alice / Bob / Carol による revoke + rotation のマルチユーザーシナリオを含む。
/// </summary>
public class E2eeV2Tests
{
    private const string VolumeId = "vol-12345678";

    private static (byte[] Pub, byte[] Priv) KeyPair() => E2eeCrypto.GenerateEcdhKeyPair();

    // ---- TOFU fingerprint ----

    [Fact]
    public void ComputeFingerprint_IsUppercaseHexSha256OfRawKey()
    {
        byte[] pub = Convert.FromHexString(
            "04A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90");
        string fp = E2eeV2.ComputeFingerprint(pub);
        string expected = Convert.ToHexString(SHA256.HashData(pub));

        Assert.Equal(expected, fp);
        Assert.Equal(64, fp.Length); // SHA-256 = 32B = 64 hex chars
        Assert.Equal(fp, fp.ToUpperInvariant());
    }

    [Fact]
    public void ComputeFingerprint_DiffersForDifferentKeys()
    {
        var (alicePub, _) = KeyPair();
        var (bobPub, _) = KeyPair();

        string fpA = E2eeV2.ComputeFingerprint(alicePub);
        string fpB = E2eeV2.ComputeFingerprint(bobPub);

        Assert.NotEqual(fpA, fpB);
        // 同一鍵なら同一 fingerprint（TOFU pin 比較の前提）
        Assert.Equal(fpA, E2eeV2.ComputeFingerprint(alicePub));
    }

    // ---- GroupKey wrap (ECDH + HKDF + AES-GCM, AAD = volumeId / keyEpoch / username) ----

    [Fact]
    public void EcdhWrapGroupKey_Roundtrip_UnwrapsWithRecipientKey()
    {
        var (alicePub, _) = KeyPair();
        var (bobPub, bobPriv) = KeyPair();
        byte[] groupKey = E2eeV2.GenerateGroupKey();

        var (ephPub, nonce, ct, tag) = E2eeV2.EcdhWrapGroupKey(groupKey, bobPub, VolumeId, keyEpoch: 1, username: "bob");
        byte[] unwrapped = E2eeV2.EcdhUnwrapGroupKey(nonce, ct, tag, ephPub, bobPriv, VolumeId, keyEpoch: 1, username: "bob");

        Assert.Equal(groupKey, unwrapped);
        // alice は自分の鍵では unwrap できない（bob 宛てのラップ）
        var (_, alicePriv) = KeyPair();
        var (_, otherPriv) = KeyPair();
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeV2.EcdhUnwrapGroupKey(nonce, ct, tag, ephPub, otherPriv, VolumeId, 1, "bob"));
    }

    [Fact]
    public void EcdhWrapGroupKey_AadBindsVolumeIdEpochAndUsername()
    {
        var (bobPub, bobPriv) = KeyPair();
        byte[] groupKey = E2eeV2.GenerateGroupKey();
        var (ephPub, nonce, ct, tag) = E2eeV2.EcdhWrapGroupKey(groupKey, bobPub, VolumeId, 2, "bob");

        // AAD のどれか 1 つでも違えば復号失敗（wrap の転用・差し替え防止）
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeV2.EcdhUnwrapGroupKey(nonce, ct, tag, ephPub, bobPriv, "vol-other", 2, "bob"));
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeV2.EcdhUnwrapGroupKey(nonce, ct, tag, ephPub, bobPriv, VolumeId, 3, "bob"));
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeV2.EcdhUnwrapGroupKey(nonce, ct, tag, ephPub, bobPriv, VolumeId, 2, "carol"));
    }

    [Fact]
    public void EcdhWrapGroupKey_TamperedCiphertext_Fails()
    {
        var (bobPub, bobPriv) = KeyPair();
        byte[] groupKey = E2eeV2.GenerateGroupKey();
        var (ephPub, nonce, ct, tag) = E2eeV2.EcdhWrapGroupKey(groupKey, bobPub, VolumeId, 1, "bob");

        ct[0] ^= 0xFF;
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeV2.EcdhUnwrapGroupKey(nonce, ct, tag, ephPub, bobPriv, VolumeId, 1, "bob"));
    }

    // ---- per-file DEK wrap (AES-GCM with GroupKey, AAD = volumeId / fileId / keyEpoch) ----

    [Fact]
    public void WrapFileKey_Roundtrip_And_DekeysAreIndependentPerFile()
    {
        byte[] groupKey = E2eeV2.GenerateGroupKey();
        byte[] dek1 = E2eeV2.GenerateFileKey();
        byte[] dek2 = E2eeV2.GenerateFileKey();
        string fileA = Guid.NewGuid().ToString("N");
        string fileB = Guid.NewGuid().ToString("N");

        // ファイルごとの DEK は独立（CSPRNG）
        Assert.NotEqual(dek1, dek2);

        var (nonce1, ct1, tag1) = E2eeV2.WrapFileKey(dek1, groupKey, VolumeId, fileA, 1);
        var (nonce2, ct2, tag2) = E2eeV2.WrapFileKey(dek2, groupKey, VolumeId, fileB, 1);

        Assert.Equal(dek1, E2eeV2.UnwrapFileKey(nonce1, ct1, tag1, groupKey, VolumeId, fileA, 1));
        Assert.Equal(dek2, E2eeV2.UnwrapFileKey(nonce2, ct2, tag2, groupKey, VolumeId, fileB, 1));
    }

    [Fact]
    public void UnwrapFileKey_AadBindsVolumeIdFileIdAndEpoch()
    {
        byte[] groupKey = E2eeV2.GenerateGroupKey();
        byte[] dek = E2eeV2.GenerateFileKey();
        string fileId = Guid.NewGuid().ToString("N");
        var (nonce, ct, tag) = E2eeV2.WrapFileKey(dek, groupKey, VolumeId, fileId, 1);

        // 別ファイル・別 epoch・別ボリュームへの WrappedFileKey 差し替えは失敗する
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeV2.UnwrapFileKey(nonce, ct, tag, groupKey, VolumeId, Guid.NewGuid().ToString("N"), 1));
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeV2.UnwrapFileKey(nonce, ct, tag, groupKey, VolumeId, fileId, 2));
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeV2.UnwrapFileKey(nonce, ct, tag, groupKey, "vol-other", fileId, 1));

        // 間違った GroupKey でも失敗
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeV2.UnwrapFileKey(nonce, ct, tag, E2eeV2.GenerateGroupKey(), VolumeId, fileId, 1));
    }

    // ---- チャンク暗号化（v2: DEK + 強化 AAD + 決定的 nonce） ----

    [Fact]
    public void EncryptChunk_Roundtrip_WithFirstChunkSalt()
    {
        byte[] dek = E2eeV2.GenerateFileKey();
        byte[] salt = E2eeV2.GenerateFileSalt();
        string fileId = Guid.NewGuid().ToString("N");
        byte[] plain = RandomNumberGenerator.GetBytes(1024);
        var ctx = new E2eeChunkContext(VolumeId, fileId, 0, 0, 1);

        byte[] enc = E2eeV2.EncryptChunk(plain, dek, ctx, isFirstChunk: true, salt);
        // ワイヤ形式: [salt (16B)] || ct || tag
        Assert.Equal(E2eeCrypto.SaltSize + plain.Length + E2eeCrypto.GcmTagSize, enc.Length);

        byte[] dec = E2eeV2.DecryptChunk(enc, dek, ctx, salt);
        Assert.Equal(plain, dec);
    }

    [Fact]
    public void EncryptChunk_Roundtrip_NonFirstChunk_HasNoSaltPrefix()
    {
        byte[] dek = E2eeV2.GenerateFileKey();
        byte[] salt = E2eeV2.GenerateFileSalt();
        string fileId = Guid.NewGuid().ToString("N");
        byte[] plain = RandomNumberGenerator.GetBytes(512);
        var ctx = new E2eeChunkContext(VolumeId, fileId, 3, 0, 1);

        byte[] enc = E2eeV2.EncryptChunk(plain, dek, ctx, isFirstChunk: false, salt);
        Assert.Equal(plain.Length + E2eeCrypto.GcmTagSize, enc.Length);

        Assert.Equal(plain, E2eeV2.DecryptChunk(enc, dek, ctx, salt));
    }

    [Fact]
    public void ChunkAad_BindsEveryContextField()
    {
        byte[] dek = E2eeV2.GenerateFileKey();
        byte[] salt = E2eeV2.GenerateFileSalt();
        string fileId = Guid.NewGuid().ToString("N");
        byte[] plain = RandomNumberGenerator.GetBytes(128);

        // volumeId / fileId / chunkIndex / revision / keyEpoch のどれか 1 つでも
        // 変わると復号失敗（正規暗号文の別文脈への差し替え防止）
        (string Vol, string File, int Chunk, int Rev, int Epoch)[] mutations =
        [
            ("vol-other", fileId, 1, 0, 1),
            (VolumeId, Guid.NewGuid().ToString("N"), 1, 0, 1),
            (VolumeId, fileId, 2, 0, 1),
            (VolumeId, fileId, 1, 1, 1),
            (VolumeId, fileId, 1, 0, 2),
        ];

        foreach (var (vol, file, chunk, rev, epoch) in mutations)
        {
            var encCtx = new E2eeChunkContext(VolumeId, fileId, 1, 0, 1);
            byte[] enc = E2eeV2.EncryptChunk(plain, dek, encCtx, isFirstChunk: false, salt);
            var decCtx = new E2eeChunkContext(vol, file, chunk, rev, epoch);
            Assert.ThrowsAny<CryptographicException>(() => E2eeV2.DecryptChunk(enc, dek, decCtx, salt));
        }
    }

    [Fact]
    public void ChunkNonce_IsDeterministicPerContext_AndSeparatesBySalt()
    {
        byte[] dek = E2eeV2.GenerateFileKey();
        byte[] salt = E2eeV2.GenerateFileSalt();
        string fileId = Guid.NewGuid().ToString("N");
        byte[] plain = RandomNumberGenerator.GetBytes(64);

        var ctx = new E2eeChunkContext(VolumeId, fileId, 0, 0, 1);
        byte[] enc1 = E2eeV2.EncryptChunk(plain, dek, ctx, isFirstChunk: true, salt);
        byte[] enc2 = E2eeV2.EncryptChunk(plain, dek, ctx, isFirstChunk: true, salt);

        // nonce はコンテキスト（DEK + salt + index + revision + epoch）から決定的に導出される
        Assert.Equal(enc1, enc2);

        // salt が違えば同じ DEK + 同一平文でも暗号文は変わる（チャンク間 nonce 再利用の回避）
        byte[] encOtherSalt = E2eeV2.EncryptChunk(plain, dek, ctx, isFirstChunk: true, E2eeV2.GenerateFileSalt());
        Assert.NotEqual(enc1, encOtherSalt);
    }

    [Fact]
    public void DecryptChunk_TamperingFails()
    {
        byte[] dek = E2eeV2.GenerateFileKey();
        byte[] salt = E2eeV2.GenerateFileSalt();
        string fileId = Guid.NewGuid().ToString("N");
        byte[] plain = RandomNumberGenerator.GetBytes(128);
        var ctx = new E2eeChunkContext(VolumeId, fileId, 0, 0, 1);

        byte[] encBadCt = E2eeV2.EncryptChunk(plain, dek, ctx, isFirstChunk: true, salt);
        encBadCt[E2eeCrypto.SaltSize] ^= 0xFF; // 暗号文 1 バイト改変
        Assert.ThrowsAny<CryptographicException>(() => E2eeV2.DecryptChunk(encBadCt, dek, ctx, salt));

        byte[] encBadTag = E2eeV2.EncryptChunk(plain, dek, ctx, isFirstChunk: true, salt);
        encBadTag[^1] ^= 0xFF; // tag 1 バイト改変
        Assert.ThrowsAny<CryptographicException>(() => E2eeV2.DecryptChunk(encBadTag, dek, ctx, salt));

        byte[] encBadKey = E2eeV2.EncryptChunk(plain, dek, ctx, isFirstChunk: true, salt);
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeV2.DecryptChunk(encBadKey, E2eeV2.GenerateFileKey(), ctx, salt));
    }

    // ---- マルチユーザー epoch シナリオ（Alice = owner / Bob / Carol） ----

    [Fact]
    public void EpochScenario_RotationExcludesRevokedMember_AndRendersOldWrapsOnly()
    {
        var (alicePub, alicePriv) = KeyPair();
        var (bobPub, bobPriv) = KeyPair();
        var (carolPub, carolPriv) = KeyPair();

        // ---- epoch 1: Alice が GroupKey を生成し、全メンバー宛てに wrap ----
        byte[] groupKey1 = E2eeV2.GenerateGroupKey();
        var epoch1Wraps = new Dictionary<string, (byte[] Eph, byte[] Nonce, byte[] Ct, byte[] Tag)>
        {
            ["alice"] = E2eeV2.EcdhWrapGroupKey(groupKey1, alicePub, VolumeId, 1, "alice"),
            ["bob"] = E2eeV2.EcdhWrapGroupKey(groupKey1, bobPub, VolumeId, 1, "bob"),
            ["carol"] = E2eeV2.EcdhWrapGroupKey(groupKey1, carolPub, VolumeId, 1, "carol"),
        };

        // 3 人とも epoch 1 の GroupKey を復元できる
        Assert.Equal(groupKey1, E2eeV2.EcdhUnwrapGroupKey(
            epoch1Wraps["alice"].Nonce, epoch1Wraps["alice"].Ct, epoch1Wraps["alice"].Tag,
            epoch1Wraps["alice"].Eph, alicePriv, VolumeId, 1, "alice"));
        Assert.Equal(groupKey1, E2eeV2.EcdhUnwrapGroupKey(
            epoch1Wraps["bob"].Nonce, epoch1Wraps["bob"].Ct, epoch1Wraps["bob"].Tag,
            epoch1Wraps["bob"].Eph, bobPriv, VolumeId, 1, "bob"));
        Assert.Equal(groupKey1, E2eeV2.EcdhUnwrapGroupKey(
            epoch1Wraps["carol"].Nonce, epoch1Wraps["carol"].Ct, epoch1Wraps["carol"].Tag,
            epoch1Wraps["carol"].Eph, carolPriv, VolumeId, 1, "carol"));

        // ---- Carol 宛てに epoch 1 ファイルが作られる（DEK wrap + チャンク + ファイル名） ----
        byte[] dek = E2eeV2.GenerateFileKey();
        byte[] salt = E2eeV2.GenerateFileSalt();
        string fileId = Guid.NewGuid().ToString("N");
        var (dekNonce, dekCt, dekTag) = E2eeV2.WrapFileKey(dek, groupKey1, VolumeId, fileId, 1);
        byte[] plain = "secret document"u8.ToArray();
        byte[] chunk = E2eeV2.EncryptChunk(plain, dek, new E2eeChunkContext(VolumeId, fileId, 0, 0, 1), true, salt);
        string encryptedName = E2eeCrypto.EncryptFilename("report.txt", groupKey1);

        // ---- revoke Carol: 新 GroupKey (epoch 2) は remaining members (alice, bob) 宛てのみ ----
        byte[] groupKey2 = E2eeV2.GenerateGroupKey();
        var epoch2Wraps = new Dictionary<string, (byte[] Eph, byte[] Nonce, byte[] Ct, byte[] Tag)>
        {
            ["alice"] = E2eeV2.EcdhWrapGroupKey(groupKey2, alicePub, VolumeId, 2, "alice"),
            ["bob"] = E2eeV2.EcdhWrapGroupKey(groupKey2, bobPub, VolumeId, 2, "bob"),
        };
        Assert.False(epoch2Wraps.ContainsKey("carol")); // 削除メンバー宛ての wrap は存在しない

        // ---- rotation + rewrap: 旧 DEK を epoch 2 GroupKey に再ラップ（チャンク本体は不変） ----
        var (rewrapNonce, rewrapCt, rewrapTag) = E2eeV2.WrapFileKey(dek, groupKey2, VolumeId, fileId, 2);

        // Bob は新 wrap (epoch 2) から同じ DEK を導出でき、旧チャンク (epoch 1) も復号できる
        byte[] dekAfterRewrap = E2eeV2.UnwrapFileKey(rewrapNonce, rewrapCt, rewrapTag, groupKey2, VolumeId, fileId, 2);
        Assert.Equal(dek, dekAfterRewrap);
        Assert.Equal(plain, E2eeV2.DecryptChunk(chunk, dekAfterRewrap, new E2eeChunkContext(VolumeId, fileId, 0, 0, 1), salt));

        // Carol は epoch 2 の GroupKey を持たないため rewrap 後の DEK を取得できない
        // （epoch2Wraps に carol 宛ての wrap が無い = アンラップの手段自体が存在しない）。
        // 誤って epoch 1 の GroupKey で epoch 2 wrap を開こうとしても AAD 不一致で失敗する。
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeV2.UnwrapFileKey(rewrapNonce, rewrapCt, rewrapTag, groupKey1, VolumeId, fileId, 2));

        // ファイル名はアップロード時点 (epoch 1) の GroupKey で暗号化されたまま:
        // Bob は保持する全 epoch の GroupKey でフォールバック復号できる（epoch 2 で失敗 → epoch 1 で成功）
        Assert.ThrowsAny<CryptographicException>(() => E2eeCrypto.DecryptFilename(encryptedName, groupKey2));
        Assert.Equal("report.txt", E2eeCrypto.DecryptFilename(encryptedName!, groupKey1));
    }

    [Fact]
    public void EpochScenario_NewFilesUseNewEpoch()
    {
        var (bobPub, bobPriv) = KeyPair();
        byte[] groupKey1 = E2eeV2.GenerateGroupKey();
        byte[] groupKey2 = E2eeV2.GenerateGroupKey();

        // rotation 後に作られた新ファイルは新 epoch (2) の GroupKey で DEK を wrap する
        byte[] newDek = E2eeV2.GenerateFileKey();
        string newFileId = Guid.NewGuid().ToString("N");
        var (nonce, ct, tag) = E2eeV2.WrapFileKey(newDek, groupKey2, VolumeId, newFileId, 2);

        Assert.Equal(newDek, E2eeV2.UnwrapFileKey(nonce, ct, tag, groupKey2, VolumeId, newFileId, 2));
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeV2.UnwrapFileKey(nonce, ct, tag, groupKey1, VolumeId, newFileId, 2));
    }
}
