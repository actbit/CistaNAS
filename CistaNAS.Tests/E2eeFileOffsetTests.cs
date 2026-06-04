using CistaNAS.Web.Services;

namespace CistaNAS.Tests;

/// <summary>
/// E2eeFileService.CreateFileAsync のオフセット計算テスト。
/// 修正 #5: ChunkSizes ではなく EncryptedLength ベースでオフセットを算出する.
/// </summary>
public class E2eeFileOffsetTests
{
    // NOTE: This test class focuses on unit testing the offset calculation logic.
    // Integration tests with actual FileService are in E2eeFileTests.
    
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(100)]
    [InlineData(1024)]
    [InlineData(4096)]
    public void ComputeEncryptedLength_FormatsCorrectly(long plainSize)
    {
        // Test that EncryptedLength calculation matches the expected format:
        // encrypted = salt + plainSize + chunkCount * tag
        const int chunkSize = 1024;
        long encrypted = E2eeFileService.ComputeEncryptedLength(plainSize, chunkSize);
        long chunks = plainSize == 0 ? 1 : (plainSize + chunkSize - 1) / chunkSize;
        
        long expected = E2eeFileService.SaltSize + plainSize + chunks * E2eeFileService.TagSize;
        Assert.Equal(expected, encrypted);
    }

    [Fact]
    public void EncryptedLength_VariousSizes()
    {
        const int chunkSize = 4096;
        
        // Empty file: salt + tag
        long empty = E2eeFileService.ComputeEncryptedLength(0, chunkSize);
        Assert.Equal(E2eeFileService.SaltSize + E2eeFileService.TagSize, empty);
        
        // Exactly chunk size
        long exact = E2eeFileService.ComputeEncryptedLength(chunkSize, chunkSize);
        Assert.Equal(E2eeFileService.SaltSize + chunkSize + E2eeFileService.TagSize, exact);
        
        // One byte over chunk size (2 chunks)
        long over = E2eeFileService.ComputeEncryptedLength(chunkSize + 1, chunkSize);
        Assert.Equal(E2eeFileService.SaltSize + chunkSize + 1 + 2 * E2eeFileService.TagSize, over);
    }

    [Fact]
    public void ComputePlainSize_RoundtripFromEncrypted()
    {
        const int chunkSize = 8192;
        
        // Test multiple sizes
        long[] sizes = { 0, 1, 100, chunkSize, chunkSize + 1, chunkSize * 3 };
        foreach (long plainSize in sizes)
        {
            long encrypted = E2eeFileService.ComputeEncryptedLength(plainSize, chunkSize);
            int chunkCount = plainSize == 0 ? 1 : (int)((plainSize + chunkSize - 1) / chunkSize);
            long recovered = E2eeFileService.ComputePlainSize(encrypted, chunkCount);
            Assert.Equal(plainSize, recovered);
        }
    }
}