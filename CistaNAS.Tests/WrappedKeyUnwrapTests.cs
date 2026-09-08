using System.Security.Cryptography;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;
using CistaNAS.Shared.Crypto;
using Xunit;

namespace CistaNAS.Tests;

/// <summary>E2eeSession の wrapped-key アンラップ (password / ecdh 両 wrapType) の検証。</summary>
public class WrappedKeyUnwrapTests
{
    [Fact]
    public void passwordラップのアンラップ()
    {
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(E2eeCrypto.SaltSize);
        const int iterations = 1000;
        byte[] kek = E2eeCrypto.DeriveKek("alice", "password123", salt, iterations);
        (byte[] nonce, byte[] ct, byte[] tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        Array.Clear(kek);

        var wk = new WrappedKeyInfo
        {
            KdfAlgorithm = "pbkdf2-sha256",
            KdfIterations = iterations,
            KdfSalt = salt,
            WrapType = "password",
            WrappedNonce = nonce,
            WrappedCiphertext = ct,
            WrappedTag = tag,
        };

        var session = new E2eeSession();
        byte[] unwrapped = session.UnwrapMasterKey("alice", "password123", wk, null);
        Assert.Equal(masterKey, unwrapped);
    }

    [Fact]
    public void passwordラップは誤パスワードで失敗する()
    {
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(E2eeCrypto.SaltSize);
        byte[] kek = E2eeCrypto.DeriveKek("alice", "correct-pass", salt, 1000);
        (byte[] nonce, byte[] ct, byte[] tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        Array.Clear(kek);

        var wk = new WrappedKeyInfo
        {
            KdfAlgorithm = "pbkdf2-sha256",
            KdfIterations = 1000,
            KdfSalt = salt,
            WrapType = "password",
            WrappedNonce = nonce,
            WrappedCiphertext = ct,
            WrappedTag = tag,
        };

        var session = new E2eeSession();
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => session.UnwrapMasterKey("alice", "wrong-pass", wk, null));
    }

    [Fact]
    public void argon2id_rawラップのアンラップ()
    {
        // Argon2id 単独（PBKDF2 後段なし）でラップされた鍵もラウンドトリップできること
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(E2eeCrypto.SaltSize);
        var spec = new KdfSpec(KdfSpec.Argon2idRaw, 0, 1024, 1, 1);
        byte[] kek = E2eeCrypto.DeriveKek("alice", "password123", salt, spec);
        (byte[] nonce, byte[] ct, byte[] tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        Array.Clear(kek);

        var wk = new WrappedKeyInfo
        {
            KdfAlgorithm = "argon2id-raw",
            KdfIterations = 0,
            KdfMemoryKiB = 1024,
            KdfTimeCost = 1,
            KdfParallelism = 1,
            KdfSalt = salt,
            WrapType = "password",
            WrappedNonce = nonce,
            WrappedCiphertext = ct,
            WrappedTag = tag,
        };

        var session = new E2eeSession();
        byte[] unwrapped = session.UnwrapMasterKey("alice", "password123", wk, null);
        Assert.Equal(masterKey, unwrapped);
    }

    [Fact]
    public void ecdhラップのアンラップ()
    {
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        (byte[] recipientPub, byte[] recipientPriv) = E2eeCrypto.GenerateEcdhKeyPair();
        (byte[] ephPub, byte[] nonce, byte[] ct, byte[] tag) = E2eeCrypto.EcdhWrap(masterKey, recipientPub);

        var wk = new WrappedKeyInfo
        {
            KdfAlgorithm = "pbkdf2-sha256",
            KdfIterations = 1000,
            KdfSalt = [],
            WrapType = "ecdh",
            EphemeralPublicKey = ephPub,
            WrappedNonce = nonce,
            WrappedCiphertext = ct,
            WrappedTag = tag,
        };

        var session = new E2eeSession();
        byte[] unwrapped = session.UnwrapMasterKey("alice", null, wk, recipientPriv);
        Assert.Equal(masterKey, unwrapped);
    }

    [Fact]
    public void StoreKey_GetMasterKey_RemoveKey()
    {
        var session = new E2eeSession();
        Assert.False(session.HasKey("vol"));
        Assert.Throws<InvalidOperationException>(() => session.GetMasterKey("vol"));

        byte[] key = E2eeCrypto.GenerateMasterKey();
        session.StoreKey("vol", key, 65536);
        Assert.True(session.HasKey("vol"));
        Assert.Equal(65536, session.GetChunkSize("vol"));
        Assert.Equal(key, session.GetMasterKey("vol"));

        Assert.True(session.RemoveKey("vol"));
        Assert.False(session.HasKey("vol"));
        Assert.False(session.RemoveKey("vol"));
    }
}
