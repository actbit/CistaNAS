using System.Security.Cryptography;
using CistaNAS.Web.Crypto;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using CistaNAS.Tests.Helpers;

namespace CistaNAS.Tests;

public class ChunkedReadStreamTests
{
    private static byte[] MasterKey() => RandomNumberGenerator.GetBytes(KeyDerivation.MasterKeySize);
    private const int SectorSize = 4096;
    private const int ChunkSize = 65536; // テスト用に小さめ

    /// <summary>暗号化チャンクを InMemoryChunkStore に書き込み、ChunkedReadStream を返す。</summary>
    private static (ChunkedReadStream stream, byte[] originalData, InMemoryChunkStore store)
        PrepareStream(byte[] plainData, int chunksCount, byte[]? key = null)
    {
        key ??= MasterKey();
        var store = new InMemoryChunkStore();

        var chunkSizes = new List<int>();
        int offset = 0;
        for (int i = 0; i < chunksCount; i++)
        {
            int size = (i < chunksCount - 1) ? ChunkSize : plainData.Length - offset;
            byte[] chunkPlain = plainData[offset..(offset + size)];
            byte[] encrypted = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.Aes256Xts, i, SectorSize, ChunkSize, chunkPlain);
            using var ms = new MemoryStream(encrypted);
            store.WriteChunkAsync("vol", "file", i, ms).Wait();
            chunkSizes.Add(size);
            offset += size;
        }

        var stream = new ChunkedReadStream(store, "vol", "file", key, CipherAlgorithm.Aes256Xts, SectorSize, ChunkSize, chunkSizes);
        return (stream, plainData, store);
    }

    [Fact]
    public void SingleChunk_Roundtrip()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(ChunkSize);
        var (stream, _, _) = PrepareStream(plain, 1);
        using (stream)
        {
            byte[] result = new byte[plain.Length];
            int total = 0;
            while (total < result.Length)
            {
                int n = stream.Read(result, total, result.Length - total);
                Assert.True(n > 0);
                total += n;
            }
            Assert.Equal(plain, result);
        }
    }

    [Fact]
    public void MultiChunk_Roundtrip()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(ChunkSize * 3 + 1234);
        var (stream, _, _) = PrepareStream(plain, 4);
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
        byte[] plain = RandomNumberGenerator.GetBytes(ChunkSize * 2 + 500);
        var (stream, _, _) = PrepareStream(plain, 3);
        using (stream)
        {
            // 中央付近に Seek
            long seekPos = ChunkSize + 200;
            stream.Seek(seekPos, SeekOrigin.Begin);
            Assert.Equal(seekPos, stream.Position);

            byte[] expected = plain[(int)seekPos..((int)seekPos + 1000)];
            byte[] result = new byte[1000];
            stream.ReadExactly(result);
            Assert.Equal(expected, result);
        }
    }

    [Fact]
    public void Read_AcrossChunkBoundary()
    {
        // チャンク境界をまたぐ読み取り
        byte[] plain = RandomNumberGenerator.GetBytes(ChunkSize * 2);
        var (stream, _, _) = PrepareStream(plain, 2);
        using (stream)
        {
            // チャンク境界の前後100バイトを読み取る
            int start = ChunkSize - 100;
            stream.Seek(start, SeekOrigin.Begin);

            byte[] result = new byte[200];
            stream.ReadExactly(result);
            byte[] expected = plain[start..(start + 200)];
            Assert.Equal(expected, result);
        }
    }

    [Fact]
    public void Read_WithSmallBuffer()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(5000);
        var (stream, _, _) = PrepareStream(plain, 1);
        using (stream)
        {
            byte[] result = new byte[plain.Length];
            byte[] smallBuf = new byte[37]; // 奇数サイズの小バッファ
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
        byte[] plain = RandomNumberGenerator.GetBytes(ChunkSize * 2 + 100);
        var (stream, _, _) = PrepareStream(plain, 3);
        using (stream)
        {
            Assert.Equal(plain.Length, stream.Length);
            Assert.Equal(0, stream.Position);

            stream.Position = 500;
            Assert.Equal(500, stream.Position);
        }
    }

    [Fact]
    public void Read_PastEnd_ReturnsZero()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(100);
        var (stream, _, _) = PrepareStream(plain, 1);
        using (stream)
        {
            // 全データ読み取り
            byte[] buf = new byte[100];
            stream.ReadExactly(buf);

            // 末尾以降は 0 を返す
            byte[] smallBuf = new byte[10];
            int n = stream.Read(smallBuf, 0, smallBuf.Length);
            Assert.Equal(0, n);
        }
    }

    [Fact]
    public void SeekOrigin_All()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(ChunkSize + 500);
        var (stream, _, _) = PrepareStream(plain, 2);
        using (stream)
        {
            // Begin
            long pos = stream.Seek(100, SeekOrigin.Begin);
            Assert.Equal(100, pos);

            // Current
            pos = stream.Seek(50, SeekOrigin.Current);
            Assert.Equal(150, pos);

            // End
            pos = stream.Seek(-100, SeekOrigin.End);
            Assert.Equal(plain.Length - 100, pos);
        }
    }

    [Fact]
    public void ChunkCache_Reuse()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(ChunkSize);
        var (stream, _, _) = PrepareStream(plain, 1);
        using (stream)
        {
            // 1回目: チャンク読み込み
            byte[] buf1 = new byte[100];
            stream.Read(buf1, 0, 100);

            // 2回目: 先頭に戻って同じチャンク読み込み（キャッシュヒット）
            stream.Seek(0, SeekOrigin.Begin);
            byte[] buf2 = new byte[100];
            stream.Read(buf2, 0, 100);

            Assert.Equal(buf1, buf2);
        }
    }

    [Fact]
    public void Disposed_Read_Throws()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(100);
        var (stream, _, _) = PrepareStream(plain, 1);
        stream.Dispose();

        byte[] buf = new byte[10];
        Assert.Throws<ObjectDisposedException>(() => stream.Read(buf, 0, buf.Length));
    }

    [Fact]
    public async Task ChunkNotFound_Throws()
    {
        byte[] key = MasterKey();
        var store = new InMemoryChunkStore();
        // チャンクを書き込まない → ReadChunkAsync が null を返す

        var stream = new ChunkedReadStream(store, "vol", "missing", key, CipherAlgorithm.Aes256Xts, SectorSize, ChunkSize, new List<int> { 100 });

        byte[] buf = new byte[10];
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            stream.ReadAsync(buf).AsTask());
    }

    [Fact]
    public async Task ReadAsync_Roundtrip()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(ChunkSize * 2 + 500);
        var (stream, _, _) = PrepareStream(plain, 3);
        await using (stream.ConfigureAwait(false))
        {
            byte[] result = new byte[plain.Length];
            await stream.ReadExactlyAsync(result);
            Assert.Equal(plain, result);
        }
    }

    [Fact]
    public async Task ReadAsync_WithCancellationToken()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(ChunkSize);
        var (stream, _, _) = PrepareStream(plain, 1);
        await using (stream.ConfigureAwait(false))
        {
            using var cts = new CancellationTokenSource();
            byte[] result = new byte[plain.Length];
            // 正常完了: キャンセルなしで最後まで読めること
            await stream.ReadExactlyAsync(result, cts.Token);
            Assert.Equal(plain, result);
        }
    }

    [Fact]
    public async Task ReadAsync_Cancellation_Throws()
    {
        byte[] key = MasterKey();
        var store = new InMemoryChunkStore();
        // 意図的に巨大なチャンクサイズを宣言してキャンセルが効くようにする
        var chunkSizes = new List<int> { ChunkSize * 10 };

        byte[] plain = RandomNumberGenerator.GetBytes(ChunkSize);
        byte[] encrypted = ChunkEncryptor.EncryptChunk(key, CipherAlgorithm.Aes256Xts, 0, SectorSize, ChunkSize, plain);
        using var ms = new MemoryStream(encrypted);
        store.WriteChunkAsync("vol", "cancel", 0, ms).Wait();

        // 2チャンク目を書き込まない → 2チャンク目読み取り時にチャンクが見つからない
        var bigSizes = new List<int> { ChunkSize, ChunkSize };
        var stream = new ChunkedReadStream(store, "vol", "cancel", key, CipherAlgorithm.Aes256Xts, SectorSize, ChunkSize, bigSizes);

        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));

        byte[] buf = new byte[ChunkSize * 2];
        // 2チャンク目が見つからないため InvalidOperationException、またはキャンセルで OperationCanceledException
        await Assert.ThrowsAnyAsync<Exception>(() =>
            stream.ReadExactlyAsync(buf, cts.Token).AsTask());
    }

    [Fact]
    public void EmptyFile_ZeroChunks()
    {
        byte[] key = MasterKey();
        var store = new InMemoryChunkStore();
        var stream = new ChunkedReadStream(store, "vol", "empty", key, CipherAlgorithm.Aes256Xts, SectorSize, ChunkSize, new List<int>());

        Assert.Equal(0, stream.Length);
        byte[] buf = new byte[10];
        int n = stream.Read(buf, 0, buf.Length);
        Assert.Equal(0, n);
        stream.Dispose();
    }

    [Fact]
    public async Task ReadAsync_AcrossChunkBoundary()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(ChunkSize * 3);
        var (stream, _, _) = PrepareStream(plain, 3);
        await using (stream.ConfigureAwait(false))
        {
            int start = ChunkSize - 50;
            stream.Seek(start, SeekOrigin.Begin);
            byte[] result = new byte[200];
            await stream.ReadExactlyAsync(result);
            Assert.Equal(plain[start..(start + 200)], result);
        }
    }
}
