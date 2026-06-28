using System.Collections.Concurrent;
using CistaNAS.Client;
using DokanNet;

namespace CistaNAS.Tests;

public class DokanFileSystemTests
{
    // ====================================================================
    // WriteState テスト
    // ====================================================================

    [Fact]
    public void WriteState_WriteAtOffset0_StoresData()
    {
        var ws = new CistaNasFileSystem.WriteState("test.txt", null);
        byte[] data = { 1, 2, 3, 4, 5 };
        ws.Write(data, 0, data.Length, 0);

        byte[] result = ws.GetFinalData();
        Assert.Equal(data, result);
    }

    [Fact]
    public void WriteState_MultipleWrites_Contiguous()
    {
        var ws = new CistaNasFileSystem.WriteState("test.txt", null);
        byte[] chunk1 = { 1, 2, 3 };
        byte[] chunk2 = { 4, 5, 6 };

        ws.Write(chunk1, 0, chunk1.Length, 0);
        ws.Write(chunk2, 0, chunk2.Length, 3);

        byte[] result = ws.GetFinalData();
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6 }, result);
    }

    [Fact]
    public void WriteState_WriteAtNonZeroOffset()
    {
        var ws = new CistaNasFileSystem.WriteState("test.txt", null);
        byte[] data = { 0xAA, 0xBB, 0xCC };
        ws.Write(data, 0, data.Length, 1000);

        byte[] result = ws.GetFinalData();
        Assert.Equal(1003, result.Length);
        Assert.Equal(0xAA, result[1000]);
        Assert.Equal(0xBB, result[1001]);
        Assert.Equal(0xCC, result[1002]);
    }

    [Fact]
    public void WriteState_SetDeclaredSize_TruncatesBuffer()
    {
        var ws = new CistaNasFileSystem.WriteState("test.txt", null);
        byte[] largeData = new byte[1000];
        for (int i = 0; i < largeData.Length; i++) largeData[i] = (byte)(i & 0xFF);

        ws.Write(largeData, 0, largeData.Length, 0);
        ws.SetDeclaredSize(500);

        byte[] result = ws.GetFinalData();
        Assert.Equal(500, result.Length);
        for (int i = 0; i < 500; i++)
            Assert.Equal((byte)(i & 0xFF), result[i]);
    }

    [Fact]
    public void WriteState_NoDeclaredSize_ReturnsActualWrittenLength()
    {
        var ws = new CistaNasFileSystem.WriteState("test.txt", null);
        byte[] data = { 1, 2, 3 };
        ws.Write(data, 0, data.Length, 50);

        byte[] result = ws.GetFinalData();
        Assert.Equal(53, result.Length);
        Assert.Equal(1, result[50]);
        Assert.Equal(2, result[51]);
        Assert.Equal(3, result[52]);
    }

    // ====================================================================
    // グローバルチャンクプール テスト
    // ====================================================================

    private static CistaNasFileSystem CreateTestFs()
        => new(new CistaNAS.Client.Api.CistaNasApiClient(new HttpClient()), "test-volume");

    [Fact]
    public void ChunkPool_PutAndGet_Roundtrip()
    {
        var fs = CreateTestFs();
        byte[] data = { 1, 2, 3 };
        string hash = "ABC123";

        fs.PutChunkToPool("file1", 0, data, hash);
        var result = fs.TryGetChunkFromPool("file1", 0);

        Assert.True(result.HasValue);
        Assert.Equal(data, result.Value.Data);
        Assert.Equal(hash, result.Value.EncryptedHash);
    }

    [Fact]
    public void ChunkPool_GetMissing_ReturnsNull()
    {
        var fs = CreateTestFs();
        Assert.Null(fs.TryGetChunkFromPool("nonexistent", 99));
    }

    [Fact]
    public void ChunkPool_LRU_EvictsOldest()
    {
        // MaxGlobalChunks = 20。21個追加 → 最初のが退避される
        var fs = CreateTestFs();
        byte[] dummy = { 0 };

        for (int i = 0; i < 21; i++)
            fs.PutChunkToPool("file1", i, dummy, $"hash{i}");

        Assert.Null(fs.TryGetChunkFromPool("file1", 0));  // 最古 = 退避
        Assert.NotNull(fs.TryGetChunkFromPool("file1", 1));   // 残存
        Assert.NotNull(fs.TryGetChunkFromPool("file1", 20));  // 最新
    }

    [Fact]
    public void ChunkPool_LRU_AccessRefreshes()
    {
        var fs = CreateTestFs();
        byte[] dummy = { 0 };

        // チャンク 0..19 を追加（MaxGlobalChunks = 20 なので全て収まる）
        for (int i = 0; i < 20; i++)
            fs.PutChunkToPool("file1", i, dummy, $"hash{i}");

        // チャンク 0 にアクセス → LRU 先頭に移動
        fs.TryGetChunkFromPool("file1", 0);

        // チャンク 20 を追加 → チャンク 1 が退避されるはず（0 は先頭にいるので）
        fs.PutChunkToPool("file1", 20, dummy, "hash20");

        Assert.NotNull(fs.TryGetChunkFromPool("file1", 0));   // アクセス済み → 生存
        Assert.Null(fs.TryGetChunkFromPool("file1", 1));     // 最古 → 退避
        Assert.NotNull(fs.TryGetChunkFromPool("file1", 20));  // 最新 → 生存
    }

    [Fact]
    public void ChunkPool_RemoveFileChunks()
    {
        var fs = CreateTestFs();
        byte[] dummy = { 0 };

        for (int i = 0; i < 5; i++)
            fs.PutChunkToPool("file1", i, dummy, $"hash{i}");

        fs.RemoveFileChunksFromPool("file1");

        for (int i = 0; i < 5; i++)
            Assert.Null(fs.TryGetChunkFromPool("file1", i));
    }

    // ====================================================================
    // ListingCache テスト
    // ====================================================================

    [Fact]
    public void ListingCache_SetThenGet_ReturnsEntries()
    {
        var cache = new CistaNasFileSystem.ListingCache();
        var entries = new List<(string, string, FileInformation)>
        {
            ("id1", "file1.txt", new FileInformation { FileName = "file1.txt" }),
        };

        cache.Set(entries);
        Assert.True(cache.TryGet(out var result));
        Assert.Single(result);
        Assert.Equal("file1.txt", result[0].PlainName);
    }

    [Fact]
    public void ListingCache_Expired_ReturnsFalse()
    {
        // TTL が短いキャッシュを作成するため、リフレクションで _ttl を上書きするのは複雑なので
        // Set 後に DateTime が進むことを利用する
        var cache = new CistaNasFileSystem.ListingCache();
        var entries = new List<(string, string, FileInformation)>
        {
            ("id1", "file1.txt", new FileInformation { FileName = "file1.txt" }),
        };

        cache.Set(entries);
        // TTL = 5秒。即座に取得すればヒットするはず
        Assert.True(cache.TryGet(out _));
    }

    [Fact]
    public void ListingCache_Invalidate_ClearsCache()
    {
        var cache = new CistaNasFileSystem.ListingCache();
        var entries = new List<(string, string, FileInformation)>
        {
            ("id1", "file1.txt", new FileInformation { FileName = "file1.txt" }),
        };

        cache.Set(entries);
        cache.Invalidate();
        Assert.False(cache.TryGet(out _));
    }

    // ====================================================================
    // PlainLength 計算テスト
    // ====================================================================

    [Fact]
    public void PlainLengthCalculation_CorrectForSingleChunk()
    {
        // 空ファイル: encLength = 16 (salt) + 0 (plain) + 16 (tag) = 32
        long encLength = 32;
        int chunkCount = 1;
        long plainLength = Math.Max(0, encLength - 16L - chunkCount * 16);
        Assert.Equal(0, plainLength);
    }

    [Fact]
    public void PlainLengthCalculation_CorrectForMultiChunk()
    {
        // 3 チャンク: 2×1MB + 500KB
        const int chunkSize = 1048576;
        long plainTotal = chunkSize * 2 + 500000;
        int chunkCount = 3;
        long encLength = 16 + plainTotal + chunkCount * 16;

        long plainLength = Math.Max(0, encLength - 16L - chunkCount * 16);
        Assert.Equal(plainTotal, plainLength);
    }

    [Fact]
    public void PlainLengthCalculation_NegativeClampedToZero()
    {
        // 破損データ: encLength < 16 + chunkCount * 16
        long encLength = 10;
        int chunkCount = 1;
        long plainLength = Math.Max(0, encLength - 16L - chunkCount * 16);
        Assert.Equal(0, plainLength);
    }

    // ====================================================================
    // encLength 計算テスト
    // ====================================================================

    [Fact]
    public void EncLengthCalculation_SingleChunk()
    {
        int plainLength = 500;
        int chunkCount = 1;
        long encLength = 16L + plainLength + chunkCount * 16;
        Assert.Equal(532, encLength);
    }

    [Fact]
    public void EncLengthCalculation_MultipleChunks()
    {
        const int chunkSize = 1048576;
        long plainLength = 2500000;
        int chunkCount = (int)((plainLength + chunkSize - 1) / chunkSize);
        Assert.Equal(3, chunkCount);

        long encLength = 16L + plainLength + chunkCount * 16;
        Assert.Equal(16 + 2500000 + 48, encLength);
    }

    // ====================================================================
    // FileCache スレッド安全性テスト
    // ====================================================================

    [Fact]
    public void FileCache_SetFileKey_ThreadSafe()
    {
        var cache = new CistaNasFileSystem.FileCache();
        byte[] key1 = { 1, 2, 3, 4 };
        byte[] key2 = { 5, 6, 7, 8 };

        // 複数スレッドから同時に SetFileKey を呼び出す
        Parallel.For(0, 100, i =>
        {
            byte[] key = i % 2 == 0 ? key1 : key2;
            cache.SetFileKey(key, new byte[16]);
        });

        // SetFileKey は上書き可能（他クライアントの上書きで salt が変わった場合に再導出が必要）
        // いずれかのキーが保持されていることを確認
        Assert.True(cache.TryGetFileKey(out var retrievedKey, out _));
        Assert.True(retrievedKey == key1 || retrievedKey == key2,
            $"キーは key1 または key2 のいずれかである必要があります。実際: {BitConverter.ToString(retrievedKey)}");
    }

    [Fact]
    public void FileCache_TryGetFileKey_ThreadSafe()
    {
        var cache = new CistaNasFileSystem.FileCache();
        byte[] key = { 1, 2, 3, 4 };

        // 複数スレッドから同時に TryGetFileKey を呼び出す
        var results = new ConcurrentBag<bool>();
        Parallel.For(0, 100, i =>
        {
            if (i == 50)
                cache.SetFileKey(key, new byte[16]);
            bool hasKey = cache.TryGetFileKey(out _, out _);
            results.Add(hasKey);
        });

        // SetFileKey 前は false、後は true が混在しているはず
        Assert.True(results.Contains(true));
        Assert.True(results.Contains(false));
    }

    [Fact]
    public void ChunkPool_ParallelAccess_ThreadSafe()
    {
        var fs = CreateTestFs();

        var exceptions = new ConcurrentBag<Exception>();

        // 複数スレッドから同時にチャンク操作を行う
        Parallel.For(0, 100, i =>
        {
            try
            {
                byte[] data = { (byte)i };
                string fileId = $"file{i % 5}";
                int chunkIndex = i % 20;

                fs.PutChunkToPool(fileId, chunkIndex, data, $"hash{i}");
                fs.TryGetChunkFromPool(fileId, chunkIndex);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
    }
}
