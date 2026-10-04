using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;
using CistaNAS.Tests.Helpers;
using CistaNAS.Web.Services;
using CistaNAS.Web.Services.Streams;

namespace CistaNAS.Tests;

public sealed class DownloadBufferValidationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidCrossChunkRead_DoesNotConsumeDataOrModifyBuffer(bool encrypted)
    {
        using var streamLock = new SemaphoreSlim(1, 1);
        using Stream stream = await CreateStreamAsync(encrypted ? "encrypted" : "chunk", streamLock);
        byte[] buffer = new byte[3];
        Assert.ThrowsAny<ArgumentException>(() => stream.Read(buffer, 0, 5));
        Assert.Equal(0, stream.Position);
        Assert.Equal(new byte[3], buffer);
        byte[] valid = new byte[4];
        stream.ReadExactly(valid);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, valid);
    }

    [Theory]
    [InlineData("file")]
    [InlineData("sub")]
    [InlineData("chunk")]
    [InlineData("encrypted")]
    public async Task InvalidCount_IsNotHiddenByClampingToFileLength(string kind)
    {
        using var streamLock = new SemaphoreSlim(1, 1);
        using Stream stream = await CreateStreamAsync(kind, streamLock);
        byte[] buffer = new byte[4];
        Assert.ThrowsAny<ArgumentException>(() => stream.Read(buffer, 0, 8));
        Assert.Equal(0, stream.Position);
        Assert.Equal(new byte[4], buffer);
    }

    [Theory]
    [InlineData("file")]
    [InlineData("sub")]
    [InlineData("chunk")]
    [InlineData("encrypted")]
    public async Task InvalidArguments_AreRejectedEvenAtEndOfFile(string kind)
    {
        using var streamLock = new SemaphoreSlim(1, 1);
        using Stream stream = await CreateStreamAsync(kind, streamLock);
        await stream.ReadExactlyAsync(new byte[4]);
        Assert.ThrowsAny<ArgumentException>(() => stream.Read(null!, 0, 0));
        Assert.ThrowsAny<ArgumentException>(() => stream.Read(new byte[4], -1, 1));
        Assert.ThrowsAny<ArgumentException>(() => stream.Read(new byte[4], 0, -1));
        Assert.ThrowsAny<ArgumentException>(() => stream.Read(new byte[4], 5, 0));
        Assert.ThrowsAny<ArgumentException>(() => stream.Read(new byte[4], 0, 5));
        Assert.Equal(4, stream.Position);
        Assert.Equal(0, stream.Read(new byte[4], 4, 0));
    }

    private static async Task<Stream> CreateStreamAsync(string kind, SemaphoreSlim streamLock)
    {
        if (kind == "file") return new FileSubStream(new MemoryStream(new byte[] { 1, 2, 3, 4 }), 0, 4, streamLock);
        if (kind == "sub") return new SubStream(new MemoryStream(new byte[] { 1, 2, 3, 4 }), 4);
        var store = new InMemoryChunkStore();
        byte[] key = RandomNumberGenerator.GetBytes(64);
        for (int i = 0; i < 2; i++)
        {
            byte[] data = [(byte)(i * 2 + 1), (byte)(i * 2 + 2)];
            if (kind == "encrypted")
                data = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.Aes256Xts, i, 512, 4096, data);
            await store.WriteChunkAsync("vol", "file", i, new MemoryStream(data));
        }
        return kind == "encrypted"
            ? new ChunkedReadStream(store, "vol", "file", key, CipherAlgorithm.Aes256Xts, 512, 4096, [2, 2])
            : new MemoryChunkedStream(store, "vol", "file", [2, 2]);
    }
}
