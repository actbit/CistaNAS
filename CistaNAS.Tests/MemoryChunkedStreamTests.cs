using System.Security.Cryptography;
using CistaNAS.Web.Services.Streams;
using CistaNAS.Web.Storage;
using CistaNAS.Tests.Helpers;

namespace CistaNAS.Tests;

public class MemoryChunkedStreamTests
{
    private static Stream CreateMemoryChunkedStream(IChunkStore store, string vol, string obj, IReadOnlyList<int> chunkSizes)
        => new MemoryChunkedStream(store, vol, obj, chunkSizes);

    private static (Stream stream, byte[] originalData) PrepareStream(byte[] data, int chunkSize)
    {
        var store = new InMemoryChunkStore();
        var chunkSizes = new List<int>();
        int offset = 0;
        int index = 0;

        while (offset < data.Length)
        {
            int size = Math.Min(chunkSize, data.Length - offset);
            byte[] chunk = data[offset..(offset + size)];
            using var ms = new MemoryStream(chunk);
            store.WriteChunkAsync("vol", "obj", index, ms).Wait();
            chunkSizes.Add(size);
            offset += size;
            index++;
        }

        var stream = CreateMemoryChunkedStream(store, "vol", "obj", chunkSizes);
        return (stream, data);
    }

    [Fact]
    public void SingleChunk_Roundtrip()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(500);
        var (stream, _) = PrepareStream(plain, 1024);
        using (stream)
        {
            byte[] result = new byte[plain.Length];
            stream.ReadExactly(result);
            Assert.Equal(plain, result);
        }
    }

    [Fact]
    public void MultiChunk_Roundtrip()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(3000);
        var (stream, _) = PrepareStream(plain, 1024);
        using (stream)
        {
            byte[] result = new byte[plain.Length];
            stream.ReadExactly(result);
            Assert.Equal(plain, result);
        }
    }

    [Fact]
    public void Seek_And_Read()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(3000);
        var (stream, _) = PrepareStream(plain, 1024);
        using (stream)
        {
            stream.Seek(1500, SeekOrigin.Begin);
            byte[] result = new byte[500];
            stream.ReadExactly(result);
            Assert.Equal(plain[1500..2000], result);
        }
    }

    [Fact]
    public void Read_AcrossChunkBoundary()
    {
        const int chunkSize = 1024;
        byte[] plain = RandomNumberGenerator.GetBytes(chunkSize * 2);
        var (stream, _) = PrepareStream(plain, chunkSize);
        using (stream)
        {
            int start = chunkSize - 100;
            stream.Seek(start, SeekOrigin.Begin);
            byte[] result = new byte[200];
            stream.ReadExactly(result);
            Assert.Equal(plain[start..(start + 200)], result);
        }
    }

    [Fact]
    public void Read_WithSmallBuffer()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(2000);
        var (stream, _) = PrepareStream(plain, 1024);
        using (stream)
        {
            byte[] result = new byte[plain.Length];
            byte[] smallBuf = new byte[37];
            int totalRead = 0;
            while (totalRead < plain.Length)
            {
                int n = stream.Read(smallBuf, 0, Math.Min(smallBuf.Length, plain.Length - totalRead));
                Assert.True(n > 0);
                Buffer.BlockCopy(smallBuf, 0, result, totalRead, n);
                totalRead += n;
            }
            Assert.Equal(plain, result);
        }
    }

    [Fact]
    public void Position_And_Length()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(3000);
        var (stream, _) = PrepareStream(plain, 1024);
        using (stream)
        {
            Assert.Equal(plain.Length, stream.Length);
            Assert.Equal(0, stream.Position);

            stream.Position = 500;
            Assert.Equal(500, stream.Position);
        }
    }

    [Fact]
    public void SeekOrigin_All()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(3000);
        var (stream, _) = PrepareStream(plain, 1024);
        using (stream)
        {
            long pos = stream.Seek(100, SeekOrigin.Begin);
            Assert.Equal(100, pos);

            pos = stream.Seek(50, SeekOrigin.Current);
            Assert.Equal(150, pos);

            pos = stream.Seek(-100, SeekOrigin.End);
            Assert.Equal(plain.Length - 100, pos);
        }
    }

    [Fact]
    public void ChunkCache_Reuse()
    {
        const int chunkSize = 1024;
        byte[] plain = RandomNumberGenerator.GetBytes(chunkSize);
        var (stream, _) = PrepareStream(plain, chunkSize);
        using (stream)
        {
            byte[] buf1 = new byte[100];
            stream.Read(buf1, 0, 100);

            stream.Seek(0, SeekOrigin.Begin);
            byte[] buf2 = new byte[100];
            stream.Read(buf2, 0, 100);

            Assert.Equal(buf1, buf2);
        }
    }

    [Fact]
    public async Task ReadAsync_Roundtrip()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(3000);
        var (stream, _) = PrepareStream(plain, 1024);
        await using (stream.ConfigureAwait(false))
        {
            byte[] result = new byte[plain.Length];
            await stream.ReadExactlyAsync(result);
            Assert.Equal(plain, result);
        }
    }

    [Fact]
    public async Task ReadAsync_AcrossChunkBoundary()
    {
        const int chunkSize = 1024;
        byte[] plain = RandomNumberGenerator.GetBytes(chunkSize * 3);
        var (stream, _) = PrepareStream(plain, chunkSize);
        await using (stream.ConfigureAwait(false))
        {
            stream.Seek(chunkSize - 50, SeekOrigin.Begin);
            byte[] result = new byte[200];
            await stream.ReadExactlyAsync(result);
            Assert.Equal(plain[(chunkSize - 50)..(chunkSize + 150)], result);
        }
    }
}
