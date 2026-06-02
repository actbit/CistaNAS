using CistaNAS.Web.Services;

namespace CistaNAS.Tests;

/// <summary>
/// E2eeFileService.ComputeEncryptedLength の単体テスト (C-6)。
/// 計算式が salt + chunkCount * tag + plainSize と一致することを確認。
/// </summary>
public class E2eeLengthCalcTests
{
    [Fact]
    public void ComputeEncryptedLength_EmptyFile()
    {
        long len = E2eeFileService.ComputeEncryptedLength(0, 1048576);
        // salt(16) + tag(16) = 32
        Assert.Equal(32L, len);
    }

    [Fact]
    public void ComputeEncryptedLength_OneByte()
    {
        // 1 byte ファイル: salt + 1 chunk 分の tag + 1 byte 平文
        long len = E2eeFileService.ComputeEncryptedLength(1, 1048576);
        Assert.Equal(E2eeFileService.SaltSize + 1L + E2eeFileService.TagSize, len);
    }

    [Fact]
    public void ComputeEncryptedLength_ExactlyOneChunk()
    {
        const int chunkSize = 1048576;
        long len = E2eeFileService.ComputeEncryptedLength(chunkSize, chunkSize);
        // salt + chunkSize + 1*tag
        Assert.Equal(E2eeFileService.SaltSize + chunkSize + E2eeFileService.TagSize, len);
    }

    [Fact]
    public void ComputeEncryptedLength_MultipleChunks()
    {
        const int chunkSize = 1024; // テストしやすいサイズ
        long plainSize = chunkSize * 3 + 100; // 4 チャンク
        long len = E2eeFileService.ComputeEncryptedLength(plainSize, chunkSize);
        // salt + plainSize + chunks * tag
        long expected = E2eeFileService.SaltSize + plainSize + 4L * E2eeFileService.TagSize;
        Assert.Equal(expected, len);
    }

    [Fact]
    public void ComputeEncryptedLength_NegativePlainSize_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => E2eeFileService.ComputeEncryptedLength(-1, 1024));
    }

    [Fact]
    public void ComputeEncryptedLength_ZeroChunkSize_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => E2eeFileService.ComputeEncryptedLength(100, 0));
    }
}
