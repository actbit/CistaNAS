using CistaNAS.Web.Services;

namespace CistaNAS.Tests;

/// <summary>
/// E2eeFileService.ComputePlainSize と ComputeEncryptedLength の逆関係テスト。
/// 修正 #4 で追加された ComputePlainSize の検証。
/// </summary>
public class E2eeLengthRoundtripTests
{
    [Fact]
    public void ComputePlainSize_RoundtripFromEncryptedLength()
    {
        // ComputeEncryptedLength で暗号化されたサイズから ComputePlainSize で平文を復元
        const int chunkSize = 1048576;
        
        // 0 バイト: 空ファイルでも salt(16) + tag(16) = 32 バイトの暗号化データが存在し、
        // 1チャンク相当のタグが含まれるため chunkCount=1 を指定
        long encrypted0 = E2eeFileService.ComputeEncryptedLength(0, chunkSize);
        long plain0 = E2eeFileService.ComputePlainSize(encrypted0, 1); // chunkCount=1 が正しい
        Assert.Equal(0L, plain0);

        // 1 バイト
        long encrypted1 = E2eeFileService.ComputeEncryptedLength(1, chunkSize);
        long plain1 = E2eeFileService.ComputePlainSize(encrypted1, 1);
        Assert.Equal(1L, plain1);

        // チャンクサイズちょうど
        long encryptedChunk = E2eeFileService.ComputeEncryptedLength(chunkSize, chunkSize);
        long plainChunk = E2eeFileService.ComputePlainSize(encryptedChunk, 1);
        Assert.Equal((long)chunkSize, plainChunk);

        // 複数チャンク: 2.5チャンクなので実際には3チャンクになる
        long plainMulti = chunkSize * 2 + 500;
        long encryptedMulti = E2eeFileService.ComputeEncryptedLength(plainMulti, chunkSize);
        int actualChunkCount = (int)((plainMulti + chunkSize - 1) / chunkSize);
        long recovered = E2eeFileService.ComputePlainSize(encryptedMulti, actualChunkCount);
        Assert.Equal(plainMulti, recovered);
    }

    [Fact]
    public void ComputePlainSize_LargeFile()
    {
        const int chunkSize = 1024; // 小さいチャンクでテスト
        long plainSize = chunkSize * 10 + 100;
        int chunkCount = (int)((plainSize + chunkSize - 1) / chunkSize);
        
        long encrypted = E2eeFileService.ComputeEncryptedLength(plainSize, chunkSize);
        long recovered = E2eeFileService.ComputePlainSize(encrypted, chunkCount);
        
        Assert.Equal(plainSize, recovered);
    }

    [Theory]
    [InlineData(0, 1)]  // 空ファイルは1チャンクでタグ1つ
    [InlineData(1, 1)]
    [InlineData(100, 1)]
    [InlineData(1024, 1)]
    [InlineData(1025, 2)]
    public void ComputeEncryptedLength_Then_ComputePlainSize(long plainSize, int expectedChunkCount)
    {
        const int chunkSize = 1024;
        long encrypted = E2eeFileService.ComputeEncryptedLength(plainSize, chunkSize);
        long plain = E2eeFileService.ComputePlainSize(encrypted, expectedChunkCount);
        Assert.Equal(plainSize, plain);
    }
}