using System.Security.Cryptography;
using System.Text;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

public class E2eeCryptoTests
{
    // ---- 鍵導出 ----

    [Fact]
    public void DeriveKek_IsDeterministic()
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] a = E2eeCrypto.DeriveKek("alice", "pass", salt, 1000);
        byte[] b = E2eeCrypto.DeriveKek("alice", "pass", salt, 1000);
        Assert.Equal(a, b);
    }

    [Fact]
    public void DeriveKek_DifferentPassword_ProducesDifferentKey()
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] a = E2eeCrypto.DeriveKek("alice", "pass1", salt, 1000);
        byte[] b = E2eeCrypto.DeriveKek("alice", "pass2", salt, 1000);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void DeriveKek_DifferentUsername_ProducesDifferentKey()
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] a = E2eeCrypto.DeriveKek("alice", "pass", salt, 1000);
        byte[] b = E2eeCrypto.DeriveKek("bob", "pass", salt, 1000);
        Assert.NotEqual(a, b);
    }

    // ---- マスターキー Wrap/Unwrap ----

    [Fact]
    public void WrapUnwrapMasterKey_Roundtrips()
    {
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] kek = RandomNumberGenerator.GetBytes(32);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        byte[] unwrapped = E2eeCrypto.UnwrapMasterKey(nonce, ct, tag, kek);
        Assert.Equal(masterKey, unwrapped);
    }

    [Fact]
    public void WrapMasterKey_WrongKek_Fails()
    {
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] kek = RandomNumberGenerator.GetBytes(32);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        byte[] wrongKek = RandomNumberGenerator.GetBytes(32);
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeCrypto.UnwrapMasterKey(nonce, ct, tag, wrongKek));
    }

    // ---- ファイル鍵導出 ----

    [Fact]
    public void DeriveFileKey_IsDeterministic()
    {
        byte[] mk = RandomNumberGenerator.GetBytes(32);
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] a = E2eeCrypto.DeriveFileKey(mk, salt);
        byte[] b = E2eeCrypto.DeriveFileKey(mk, salt);
        Assert.Equal(a, b);
    }

    [Fact]
    public void DeriveFileKey_DifferentSalt_ProducesDifferentKey()
    {
        byte[] mk = RandomNumberGenerator.GetBytes(32);
        byte[] a = E2eeCrypto.DeriveFileKey(mk, RandomNumberGenerator.GetBytes(16));
        byte[] b = E2eeCrypto.DeriveFileKey(mk, RandomNumberGenerator.GetBytes(16));
        Assert.NotEqual(a, b);
    }

    // ---- チャンク暗号化 ----

    [Theory]
    [InlineData(1)]
    [InlineData(100)]
    [InlineData(1048576)]
    [InlineData(1048576 + 123)]
    public void EncryptDecryptChunk_Roundtrips(int plainSize)
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        byte[] plain = RandomNumberGenerator.GetBytes(plainSize);

        byte[] enc = E2eeCrypto.EncryptChunk(plain, fileKey, 0, fileSalt, isFirstChunk: true);
        byte[] dec = E2eeCrypto.DecryptChunk(enc, fileKey, 0, out var extractedSalt);

        Assert.Equal(plain, dec);
        Assert.Equal(fileSalt, extractedSalt);
    }

    [Fact]
    public void EncryptChunk_MultipleChunks_Roundtrip()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        const int chunkSize = 1024;

        byte[][] plains = [
            RandomNumberGenerator.GetBytes(chunkSize),
            RandomNumberGenerator.GetBytes(chunkSize),
            RandomNumberGenerator.GetBytes(500),
        ];

        byte[][] encrypted = new byte[3][];
        encrypted[0] = E2eeCrypto.EncryptChunk(plains[0], fileKey, 0, fileSalt, isFirstChunk: true);
        encrypted[1] = E2eeCrypto.EncryptChunk(plains[1], fileKey, 1, fileSalt, isFirstChunk: false);
        encrypted[2] = E2eeCrypto.EncryptChunk(plains[2], fileKey, 2, fileSalt, isFirstChunk: false);

        // チャンク0は salt プレフィクス付き（16B + plain + tag 16B）
        Assert.Equal(16 + chunkSize + 16, encrypted[0].Length);
        // チャンクNは plain + tag 16B
        Assert.Equal(chunkSize + 16, encrypted[1].Length);
        Assert.Equal(500 + 16, encrypted[2].Length);

        // チャンク0からfileSaltを取得
        byte[] dec0 = E2eeCrypto.DecryptChunk(encrypted[0], fileKey, 0, out var salt0);
        Assert.Equal(plains[0], dec0);
        Assert.Equal(fileSalt, salt0);

        // 残りのチャンクを復号（fileSaltを再利用）
        for (int i = 1; i < 3; i++)
        {
            byte[] dec = E2eeCrypto.DecryptChunk(encrypted[i], fileKey, i, fileSalt);
            Assert.Equal(plains[i], dec);
        }
    }

    [Fact]
    public void EncryptChunk_SamePlaintextDifferentIndex_ProducesDifferentCiphertext()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        byte[] plain = new byte[100];
        plain.AsSpan().Fill(0x42);

        byte[] enc0 = E2eeCrypto.EncryptChunk(plain, fileKey, 0, fileSalt, isFirstChunk: false);
        byte[] enc1 = E2eeCrypto.EncryptChunk(plain, fileKey, 1, fileSalt, isFirstChunk: false);
        Assert.NotEqual(enc0, enc1);
    }

    [Fact]
    public void DecryptChunk_WrongKey_Fails()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        byte[] plain = RandomNumberGenerator.GetBytes(200);
        byte[] enc = E2eeCrypto.EncryptChunk(plain, fileKey, 0, fileSalt, isFirstChunk: true);

        byte[] wrongKey = RandomNumberGenerator.GetBytes(32);
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeCrypto.DecryptChunk(enc, wrongKey, 0, out _));
    }

    [Fact]
    public void DecryptChunk_TamperedCiphertext_Fails()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        byte[] plain = RandomNumberGenerator.GetBytes(200);
        byte[] enc = E2eeCrypto.EncryptChunk(plain, fileKey, 0, fileSalt, isFirstChunk: true);

        // 暗号文の1バイトを改ざん
        enc[^17] ^= 0xFF;
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeCrypto.DecryptChunk(enc, fileKey, 0, out _));
    }

    // ---- ファイル名暗号化 ----

    [Theory]
    [InlineData("hello.txt")]
    [InlineData("日本語ファイル名.pdf")]
    [InlineData("")]
    [InlineData("a")]
    public void EncryptDecryptFilename_Roundtrips(string plainName)
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        string enc = E2eeCrypto.EncryptFilename(plainName, masterKey);
        string dec = E2eeCrypto.DecryptFilename(enc, masterKey);
        Assert.Equal(plainName, dec);
    }

    [Fact]
    public void EncryptFilename_SameName_ProducesDifferentCiphertext()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        string enc1 = E2eeCrypto.EncryptFilename("test.txt", masterKey);
        string enc2 = E2eeCrypto.EncryptFilename("test.txt", masterKey);
        Assert.NotEqual(enc1, enc2);
        Assert.Equal("test.txt", E2eeCrypto.DecryptFilename(enc1, masterKey));
        Assert.Equal("test.txt", E2eeCrypto.DecryptFilename(enc2, masterKey));
    }

    [Fact]
    public void DecryptFilename_WrongKey_Fails()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        string enc = E2eeCrypto.EncryptFilename("secret.txt", masterKey);
        byte[] wrongKey = RandomNumberGenerator.GetBytes(32);
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeCrypto.DecryptFilename(enc, wrongKey));
    }

    // ---- E2E フロー ----

    [Fact]
    public void FullE2eeFlow_CreateWriteReadDelete()
    {
        // KEK 導出 → マスターキー生成 → Wrap → Unwrap → ファイル暗号化 → 復号
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek("alice", "password123", salt, 1000);
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();

        // Wrap/Unwrap
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        byte[] recovered = E2eeCrypto.UnwrapMasterKey(nonce, ct, tag, kek);
        Assert.Equal(masterKey, recovered);

        // ファイル名暗号化
        string plainName = "document.pdf";
        string encName = E2eeCrypto.EncryptFilename(plainName, masterKey);
        Assert.Equal(plainName, E2eeCrypto.DecryptFilename(encName, masterKey));

        // チャンク暗号化
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        byte[] plainData = RandomNumberGenerator.GetBytes(5000);

        byte[] encChunk0 = E2eeCrypto.EncryptChunk(plainData, fileKey, 0, fileSalt, isFirstChunk: true);
        byte[] decData = E2eeCrypto.DecryptChunk(encChunk0, fileKey, 0, out var extractedSalt);

        Assert.Equal(fileSalt, extractedSalt);
        Assert.Equal(plainData, decData);
    }
}
