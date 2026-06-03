using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Services;

namespace CistaNAS.Tests;

public class ChunkEncryptorTests
{
    private static byte[] MasterKey() => RandomNumberGenerator.GetBytes(KeyDerivation.MasterKeySize);

    [Fact]
    public void EncryptDecrypt_Roundtrip_SmallData()
    {
        byte[] key = MasterKey();
        byte[] plain = RandomNumberGenerator.GetBytes(123);
        const int sectorSize = 4096;
        const int chunkSize = 4194304;

        byte[] cipher = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.Aes256Xts, 0, sectorSize, chunkSize, plain);
        byte[] dec = ChunkEncryptor.DecryptChunk(key, CipherAlgorithm.Aes256Xts, 0, sectorSize, chunkSize, cipher, plain.Length);

        Assert.Equal(plain, dec);
    }

    [Fact]
    public void EncryptDecrypt_Roundtrip_LargeData()
    {
        byte[] key = MasterKey();
        const int sectorSize = 512;
        const int chunkSize = 65536;
        byte[] plain = RandomNumberGenerator.GetBytes(chunkSize - 100); // セクタ境界にまたぐサイズ

        byte[] cipher = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.Aes256Xts, 0, sectorSize, chunkSize, plain);
        byte[] dec = ChunkEncryptor.DecryptChunk(key, CipherAlgorithm.Aes256Xts, 0, sectorSize, chunkSize, cipher, plain.Length);

        Assert.Equal(plain, dec);
    }

    [Fact]
    public void EncryptDecrypt_MultipleChunks_Independent()
    {
        byte[] key = MasterKey();
        byte[] plain = RandomNumberGenerator.GetBytes(500);
        const int sectorSize = 4096;
        const int chunkSize = 4194304;

        byte[] cipher0 = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.Aes256Xts, 0, sectorSize, chunkSize, plain);
        byte[] cipher1 = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.Aes256Xts, 1, sectorSize, chunkSize, plain);

        // 異なるチャンクインデックス → 異なる暗号文
        Assert.NotEqual(cipher0, cipher1);

        // それぞれ正しく復号できること
        byte[] dec0 = ChunkEncryptor.DecryptChunk(key, CipherAlgorithm.Aes256Xts, 0, sectorSize, chunkSize, cipher0, plain.Length);
        byte[] dec1 = ChunkEncryptor.DecryptChunk(key, CipherAlgorithm.Aes256Xts, 1, sectorSize, chunkSize, cipher1, plain.Length);
        Assert.Equal(plain, dec0);
        Assert.Equal(plain, dec1);
    }

    [Fact]
    public void Decrypt_WithWrongKey_Fails()
    {
        byte[] key1 = MasterKey();
        byte[] key2 = MasterKey();
        byte[] plain = RandomNumberGenerator.GetBytes(256);
        const int sectorSize = 4096;
        const int chunkSize = 4194304;

        byte[] cipher = ChunkEncryptor.EncryptChunk(key1, CipherAlgorithm.Aes256Xts, 0, sectorSize, chunkSize, plain);
        byte[] dec = ChunkEncryptor.DecryptChunk(key2, CipherAlgorithm.Aes256Xts, 0, sectorSize, chunkSize, cipher, plain.Length);

        Assert.NotEqual(plain, dec);
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_Fails()
    {
        byte[] key = MasterKey();
        byte[] plain = RandomNumberGenerator.GetBytes(500);
        const int sectorSize = 4096;
        const int chunkSize = 4194304;

        byte[] cipher = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.Aes256Xts, 0, sectorSize, chunkSize, plain);

        // 暗号文の1バイトを改ざん
        cipher[32] ^= 0xFF;

        byte[] dec = ChunkEncryptor.DecryptChunk(key, CipherAlgorithm.Aes256Xts, 0, sectorSize, chunkSize, cipher, plain.Length);
        Assert.NotEqual(plain, dec);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 16)]
    [InlineData(15, 16)]
    [InlineData(16, 16)]
    [InlineData(17, 32)]
    [InlineData(100, 112)]
    [InlineData(4096, 4096)]
    public void PadToBlockSize_Correct(int input, int expected)
    {
        Assert.Equal(expected, ChunkEncryptor.PadToBlockSize(input));
    }

    [Theory]
    [InlineData(0, 4194304, 4096, 0)]
    [InlineData(1, 4194304, 4096, 1024)]
    [InlineData(2, 4194304, 4096, 2048)]
    [InlineData(0, 65536, 512, 0)]
    [InlineData(1, 65536, 512, 128)]
    public void GetFirstSectorIndex_Correct(int chunkIndex, int chunkSize, int sectorSize, long expectedSectors)
    {
        Assert.Equal(expectedSectors, ChunkEncryptor.GetFirstSectorIndex(chunkIndex, chunkSize, sectorSize));
    }

    [Fact]
    public void DifferentChunkIndex_DifferentCiphertext()
    {
        byte[] key = MasterKey();
        byte[] plain = new byte[4096]; // 全ゼロ
        const int sectorSize = 4096;
        const int chunkSize = 4194304;

        byte[] c0 = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.Aes256Xts, 0, sectorSize, chunkSize, plain);
        byte[] c1 = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.Aes256Xts, 1, sectorSize, chunkSize, plain);
        byte[] c2 = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.Aes256Xts, 2, sectorSize, chunkSize, plain);

        Assert.NotEqual(c0, c1);
        Assert.NotEqual(c1, c2);
        Assert.NotEqual(c0, c2);
    }

    // ---- ChaCha20 ノンス/カウンタ修正の回帰防止 (C-1) ----

    [Fact]
    public void ChaCha20_DifferentChunkIndex_DifferentCiphertext()
    {
        // 修正前: ノンスがマスター鍵から固定 → 全チャンク同一暗号文
        // 修正後: HKDF で sectorIndex からノンス派生 → 各チャンクで異なる暗号文
        // sectorSize=4096 のため、最低 1 セクタ (4096B) 以上の平文が必要。
        byte[] key = MasterKey();
        byte[] plain = RandomNumberGenerator.GetBytes(4096 * 2); // 2 セクタ分
        const int sectorSize = 4096;
        const int chunkSize = 4194304;

        byte[] c0 = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.ChaCha20, 0, sectorSize, chunkSize, plain);
        byte[] c1 = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.ChaCha20, 1, sectorSize, chunkSize, plain);

        Assert.NotEqual(c0, c1);
    }

    [Fact]
    public void ChaCha20_NonceIsUniquePerSector()
    {
        // 同じ平文・同じ鍵で sectorIndex のみ異なる → 暗号文が異なる（ECB 化していないこと）
        // sectorSize=4096 のため、最低 1 セクタ分の 4096 バイトの平文が必要。
        byte[] key = MasterKey();
        byte[] plain = RandomNumberGenerator.GetBytes(4096); // 1 セクタ
        const int sectorSize = 4096;
        const int chunkSize = 4194304;

        byte[] c0 = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.ChaCha20, 0, sectorSize, chunkSize, plain);
        byte[] c1 = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.ChaCha20, 0, sectorSize, chunkSize, plain);

        // 同じ sectorIndex + 同じ平文 → 同じ暗号文（決定論的）
        Assert.Equal(c0, c1);

        // sectorIndex を変えると暗号文も変わる
        byte[] c2 = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.ChaCha20, 1, sectorSize, chunkSize, plain);
        Assert.NotEqual(c0, c2);
    }

    [Fact]
    public void ChaCha20_DecryptRecoversPlaintext()
    {
        // 暗号化したものを復号して元に戻ることを確認
        byte[] key = MasterKey();
        byte[] plain = RandomNumberGenerator.GetBytes(64);
        const int sectorSize = 4096;
        const int chunkSize = 4194304;

        byte[] cipher = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.ChaCha20, 0, sectorSize, chunkSize, plain);
        byte[] dec = ChunkEncryptor.DecryptChunk(key, CipherAlgorithm.ChaCha20, 0, sectorSize, chunkSize, cipher, plain.Length);

        Assert.Equal(plain, dec);
    }
}
