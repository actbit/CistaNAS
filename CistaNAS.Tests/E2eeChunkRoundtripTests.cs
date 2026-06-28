using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// E2EE チャンク暗号化の fileSalt 一貫性テスト。
/// Critical-1（Dokan ReadFile の chunk>0 復号不能）の修正を検証:
/// fileSalt 引数版 DecryptChunk は chunk>0 でも共通 fileSalt で復元できること、
/// 旧 out 版は chunk>0 で fileSalt=[] を使うため失敗すること（バグの再現）。
/// </summary>
public class E2eeChunkRoundtripTests
{
    /// <summary>fileSalt 引数版で chunk>0 を含む全チャンクが正しく復号できること（修正後の経路）。</summary>
    [Fact]
    public void EncryptDecrypt_MultipleChunks_WithFileSalt_Roundtrip()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);

        byte[][] plains =
        [
            RandomNumberGenerator.GetBytes(100),
            RandomNumberGenerator.GetBytes(200),
            RandomNumberGenerator.GetBytes(50),
        ];

        for (int i = 0; i < plains.Length; i++)
        {
            byte[] enc = E2eeCrypto.EncryptChunk(plains[i], fileKey, i, fileSalt, isFirstChunk: i == 0);
            byte[] dec = E2eeCrypto.DecryptChunk(enc, fileKey, i, fileSalt);
            Assert.Equal(plains[i], dec);
        }
    }

    /// <summary>旧 out 版は chunk>0 で fileSalt=[] を使うため nonce 不一致で復号に失敗すること（バグ再現）。</summary>
    [Fact]
    public void DecryptChunk_OutOverload_ChunkGreaterThanZero_FailsWithEmptySalt()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);

        byte[] plain1 = RandomNumberGenerator.GetBytes(200);
        byte[] enc1 = E2eeCrypto.EncryptChunk(plain1, fileKey, 1, fileSalt, isFirstChunk: false);

        // out 版は chunkIndex>0 のとき fileSalt=[] となり nonce が暗号化時と不一致 → タグ検証失敗
        Assert.ThrowsAny<CryptographicException>(() =>
            E2eeCrypto.DecryptChunk(enc1, fileKey, 1, out _));
    }
}
