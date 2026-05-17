using System.Security.Cryptography;
using CistaNAS.Web.Crypto;

namespace CistaNAS.Tests;

public class CryptoTests
{
    // ---- PasswordHasher ----

    [Fact]
    public void PasswordHasher_Verifies_CorrectPassword()
    {
        string enc = PasswordHasher.Hash("s3cr3t!", 50_000);
        Assert.True(PasswordHasher.Verify("s3cr3t!", enc));
        Assert.False(PasswordHasher.Verify("wrong", enc));
    }

    [Fact]
    public void PasswordHasher_Hash_IsSalted()
    {
        Assert.NotEqual(PasswordHasher.Hash("same", 50_000), PasswordHasher.Hash("same", 50_000));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-hash")]
    [InlineData("pbkdf2-sha256$abc$x$y")]
    public void PasswordHasher_Verify_RejectsMalformed(string encoded)
    {
        Assert.False(PasswordHasher.Verify("pw", encoded));
    }

    // ---- AesXtsStream ----

    private static byte[] Key64() => RandomNumberGenerator.GetBytes(KeyDerivation.MasterKeySize);

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(100)]
    [InlineData(4096)]
    [InlineData(4097)]
    [InlineData(10_000)]
    public void AesXts_Roundtrips_AcrossSizes(int size)
    {
        byte[] key = Key64();
        byte[] plain = RandomNumberGenerator.GetBytes(size);
        const int sector = 4096;

        using var backing = new MemoryStream();
        using (var enc = new AesXtsStream(backing, key, sector, 0, writable: true, leaveOpen: true))
        {
            enc.Write(plain, 0, plain.Length);
            enc.Flush();
        }

        byte[] readBack = new byte[size];
        using (var dec = new AesXtsStream(backing, key, sector, size, writable: false, leaveOpen: true))
        {
            int total = 0;
            while (total < size)
            {
                int n = dec.Read(readBack, total, size - total);
                Assert.True(n > 0);
                total += n;
            }
        }
        Assert.Equal(plain, readBack);
    }

    [Fact]
    public void AesXts_SamePlaintext_DifferentSectors_ProducesDifferentCiphertext()
    {
        byte[] key = Key64();
        const int sector = 64;
        byte[] block = new byte[sector * 2];
        for (int i = 0; i < block.Length; i++) block[i] = 0xAB; // 2 セクタ同一平文

        using var backing = new MemoryStream();
        using (var enc = new AesXtsStream(backing, key, sector, 0, writable: true, leaveOpen: true))
            enc.Write(block, 0, block.Length);

        byte[] cipher = backing.ToArray();
        ReadOnlySpan<byte> s0 = cipher.AsSpan(0, sector);
        ReadOnlySpan<byte> s1 = cipher.AsSpan(sector, sector);
        Assert.False(s0.SequenceEqual(s1)); // トウィークがセクタ毎に効いている
    }

    [Fact]
    public void AesXts_RandomAccess_ReadModifyWrite_IsConsistent()
    {
        byte[] key = Key64();
        const int sector = 512;
        byte[] plain = RandomNumberGenerator.GetBytes(sector * 4 + 123);

        using var backing = new MemoryStream();
        using (var enc = new AesXtsStream(backing, key, sector, 0, writable: true, leaveOpen: true))
            enc.Write(plain, 0, plain.Length);

        // セクタ境界をまたぐ部分上書き
        byte[] patch = RandomNumberGenerator.GetBytes(700);
        const int patchOffset = sector - 50;
        Array.Copy(patch, 0, plain, patchOffset, patch.Length);

        using (var w = new AesXtsStream(backing, key, sector, plain.Length, writable: true, leaveOpen: true))
        {
            w.Seek(patchOffset, SeekOrigin.Begin);
            w.Write(patch, 0, patch.Length);
        }

        byte[] readBack = new byte[plain.Length];
        using (var r = new AesXtsStream(backing, key, sector, plain.Length, writable: false, leaveOpen: true))
        {
            int total = 0;
            while (total < readBack.Length)
                total += r.Read(readBack, total, readBack.Length - total);
        }
        Assert.Equal(plain, readBack);
    }

    [Fact]
    public void AesXts_WrongKey_DoesNotRecoverPlaintext()
    {
        const int sector = 256;
        byte[] plain = RandomNumberGenerator.GetBytes(1000);

        using var backing = new MemoryStream();
        using (var enc = new AesXtsStream(backing, Key64(), sector, 0, writable: true, leaveOpen: true))
            enc.Write(plain, 0, plain.Length);

        byte[] readBack = new byte[plain.Length];
        using (var dec = new AesXtsStream(backing, Key64(), sector, plain.Length, writable: false, leaveOpen: true))
        {
            int total = 0;
            while (total < readBack.Length)
                total += dec.Read(readBack, total, readBack.Length - total);
        }
        Assert.NotEqual(plain, readBack);
    }
}
