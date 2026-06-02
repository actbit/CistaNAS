using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

public class AesXtsTransformTests
{
    private static byte[] Key64() => RandomNumberGenerator.GetBytes(KeyDerivation.MasterKeySize);

    [Theory]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(512)]
    [InlineData(4096)]
    public void EncryptDecrypt_Roundtrip(int dataSize)
    {
        byte[] key = Key64();
        const int sectorSize = 16;
        byte[] plain = RandomNumberGenerator.GetBytes(dataSize);

        using var transform = new AesXtsTransform(key, sectorSize);

        byte[] cipher = new byte[dataSize];
        transform.Encrypt(0, plain, cipher);
        Assert.NotEqual(plain, cipher);

        byte[] dec = new byte[dataSize];
        transform.Decrypt(0, cipher, dec);
        Assert.Equal(plain, dec);
    }

    [Fact]
    public void DifferentSectorIndex_DifferentCiphertext()
    {
        byte[] key = Key64();
        const int sectorSize = 16;
        byte[] plain = RandomNumberGenerator.GetBytes(64);

        using var transform = new AesXtsTransform(key, sectorSize);

        byte[] c0 = new byte[64];
        byte[] c1 = new byte[64];
        transform.Encrypt(0, plain, c0);
        transform.Encrypt(1, plain, c1);

        Assert.NotEqual(c0, c1);
    }

    [Fact]
    public void MultipleBlocks_Transform()
    {
        byte[] key = Key64();
        // セクタサイズ 64 = 4 ブロック分のデータ
        const int sectorSize = 64;
        byte[] plain = RandomNumberGenerator.GetBytes(sectorSize);

        using var transform = new AesXtsTransform(key, sectorSize);

        byte[] cipher = new byte[sectorSize];
        transform.Encrypt(42, plain, cipher);

        byte[] dec = new byte[sectorSize];
        transform.Decrypt(42, cipher, dec);

        Assert.Equal(plain, dec);
    }

    [Fact]
    public void Dispose_ClearsKeys()
    {
        byte[] key = Key64();
        byte[] keyCopy = key.ToArray();

        var transform = new AesXtsTransform(key, 16);
        transform.Dispose();

        // AesXtsTransform は Dispose 時に鍵をゼロ化する。
        // 元のキー配列は外部なので影響なし。
        Assert.Equal(keyCopy, key);

        // Dispose 後に使用すると例外が発生する
        Assert.ThrowsAny<Exception>(() =>
        {
            byte[] buf = new byte[16];
            transform.Encrypt(0, buf, buf);
        });
    }
}
