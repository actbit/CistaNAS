using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// E2eeCrypto.ComputeChunkCount（プロトコル canonical のチャンク数計算）の単体テスト。
/// クライアント・サーバー・Wasm・Mobile 各実装が手書き式を持つと
/// 「空ファイルの扱い」「端数チャンクの切り上げ」で揺れて整合性検証に失敗するため、
/// この共有関数への一元化を固定する（回帰: Wasm / Mobile / Files.razor の手書き式ドリフト）。
/// </summary>
public class ComputeChunkCountTests
{
    private const int ChunkSize = 4096;

    [Theory]
    [InlineData(0, 1)]      // 空ファイルはチャンク 1（プロトコル上 salt + GCM タグのみの特殊チャンク）
    [InlineData(1, 1)]
    [InlineData(4095, 1)]
    [InlineData(4096, 1)]
    [InlineData(4097, 2)]
    [InlineData(8192, 2)]
    [InlineData(8193, 3)]
    public void 平文長からチャンク数を計算する(long plainSize, int expected)
        => Assert.Equal(expected, E2eeCrypto.ComputeChunkCount(plainSize, ChunkSize));

    [Fact]
    public void 端数は切り上げで0だけ特殊扱いする()
    {
        for (long p = 0; p <= ChunkSize * 3 + 1; p++)
        {
            int expected = p == 0 ? 1 : (int)((p + ChunkSize - 1) / ChunkSize);
            Assert.Equal(expected, E2eeCrypto.ComputeChunkCount(p, ChunkSize));
        }
    }

    [Fact]
    public void 暗号化長はチャンク数の共有関数と一致する()
    {
        // ComputeEncryptedLength 内のチャンク数計算が ComputeChunkCount に一元化されていること。
        // 手書き式（empty=0 チャンク / ceil の揺れ）の再発防止。
        for (long p = 0; p <= ChunkSize * 2 + 7; p++)
        {
            long expected = E2eeCrypto.SaltSize + p + (long)E2eeCrypto.GcmTagSize * E2eeCrypto.ComputeChunkCount(p, ChunkSize);
            Assert.Equal(expected, E2eeCrypto.ComputeEncryptedLength(p, ChunkSize));
        }
    }

    [Fact]
    public void 負のサイズと無効なチャンクサイズは拒否される()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => E2eeCrypto.ComputeChunkCount(-1, ChunkSize));
        Assert.Throws<ArgumentOutOfRangeException>(() => E2eeCrypto.ComputeChunkCount(0, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => E2eeCrypto.ComputeChunkCount(0, -1));
    }
}
