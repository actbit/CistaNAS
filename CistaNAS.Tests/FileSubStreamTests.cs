using System.Security.Cryptography;
using CistaNAS.Web.Services;

namespace CistaNAS.Tests;

public class FileSubStreamTests
{
    private static readonly Type? FileSubStreamType =
        typeof(FileService).Assembly.GetTypes()
            .FirstOrDefault(t => t.Name.EndsWith("__FileSubStream") && typeof(Stream).IsAssignableFrom(t));

    private static Stream CreateFileSubStream(Stream baseStream, long offset, long length, SemaphoreSlim streamLock)
    {
        Assert.NotNull(FileSubStreamType);
        return (Stream)Activator.CreateInstance(FileSubStreamType!, baseStream, offset, length, streamLock)!;
    }

    private static (Stream subStream, MemoryStream baseStream, byte[] data, SemaphoreSlim lock_) PrepareStream(
        int totalSize, long offset, long length)
    {
        byte[] data = RandomNumberGenerator.GetBytes(totalSize);
        var baseStream = new MemoryStream(data);
        var lock_ = new SemaphoreSlim(1, 1);
        var subStream = CreateFileSubStream(baseStream, offset, length, lock_);
        return (subStream, baseStream, data, lock_);
    }

    [Fact]
    public void Read_FullRange()
    {
        byte[] data = RandomNumberGenerator.GetBytes(1000);
        using var baseStream = new MemoryStream(data);
        var lock_ = new SemaphoreSlim(1, 1);
        using var sub = CreateFileSubStream(baseStream, 0, 1000, lock_);

        byte[] result = new byte[1000];
        sub.ReadExactly(result);
        Assert.Equal(data, result);
    }

    [Fact]
    public void Read_PartialRange()
    {
        byte[] data = RandomNumberGenerator.GetBytes(1000);
        using var baseStream = new MemoryStream(data);
        var lock_ = new SemaphoreSlim(1, 1);

        // オフセット 200 から 300 バイト
        using var sub = CreateFileSubStream(baseStream, 200, 300, lock_);
        byte[] result = new byte[300];
        sub.ReadExactly(result);
        Assert.Equal(data[200..500], result);
    }

    [Fact]
    public void Seek_And_Read()
    {
        byte[] data = RandomNumberGenerator.GetBytes(1000);
        using var baseStream = new MemoryStream(data);
        var lock_ = new SemaphoreSlim(1, 1);
        using var sub = CreateFileSubStream(baseStream, 100, 500, lock_);

        sub.Seek(200, SeekOrigin.Begin);
        byte[] result = new byte[50];
        sub.ReadExactly(result);
        Assert.Equal(data[300..350], result);
    }

    [Fact]
    public void Read_PastEnd_ReturnsZero()
    {
        var (sub, baseStream, _, lock_) = PrepareStream(1000, 0, 100);
        using (sub)
        using (baseStream)
        {
            byte[] buf = new byte[100];
            sub.ReadExactly(buf); // 全データ消費

            byte[] smallBuf = new byte[10];
            int n = sub.Read(smallBuf, 0, smallBuf.Length);
            Assert.Equal(0, n);
        }
        lock_.Dispose();
    }

    [Fact]
    public async Task ReadAsync_Roundtrip()
    {
        byte[] data = RandomNumberGenerator.GetBytes(1000);
        using var baseStream = new MemoryStream(data);
        var lock_ = new SemaphoreSlim(1, 1);
        using var sub = CreateFileSubStream(baseStream, 100, 500, lock_);

        byte[] result = new byte[500];
        await sub.ReadExactlyAsync(result);
        Assert.Equal(data[100..600], result);
    }

    [Fact]
    public void SeekOrigin_All()
    {
        var (sub, baseStream, _, lock_) = PrepareStream(1000, 100, 500);
        using (sub)
        using (baseStream)
        {
            // Begin
            long pos = sub.Seek(50, SeekOrigin.Begin);
            Assert.Equal(50, pos);

            // Current
            pos = sub.Seek(100, SeekOrigin.Current);
            Assert.Equal(150, pos);

            // End
            pos = sub.Seek(-50, SeekOrigin.End);
            Assert.Equal(450, pos);
        }
        lock_.Dispose();
    }

    [Fact]
    public async Task Concurrent_Reads()
    {
        byte[] data = RandomNumberGenerator.GetBytes(10000);
        var baseStream = new MemoryStream(data);
        var streamLock = new SemaphoreSlim(1, 1);

        // 2つの FileSubStream が同じ基底ストリームの異なる範囲を参照
        var sub1 = CreateFileSubStream(baseStream, 0, 5000, streamLock);
        var sub2 = CreateFileSubStream(baseStream, 5000, 5000, streamLock);

        var results = new byte[2][];
        var tasks = new Task[2];

        tasks[0] = Task.Run(async () =>
        {
            var buf = new byte[5000];
            await sub1.ReadExactlyAsync(buf);
            results[0] = buf;
        });

        tasks[1] = Task.Run(async () =>
        {
            var buf = new byte[5000];
            await sub2.ReadExactlyAsync(buf);
            results[1] = buf;
        });

        await Task.WhenAll(tasks);

        Assert.Equal(data[0..5000], results[0]);
        Assert.Equal(data[5000..10000], results[1]);

        sub1.Dispose();
        sub2.Dispose();
        streamLock.Dispose();
    }

    [Fact]
    public void Read_ZeroLength_ReturnsZero()
    {
        byte[] data = RandomNumberGenerator.GetBytes(100);
        using var baseStream = new MemoryStream(data);
        var lock_ = new SemaphoreSlim(1, 1);
        using var sub = CreateFileSubStream(baseStream, 50, 0, lock_);

        Assert.Equal(0, sub.Length);
        byte[] buf = new byte[10];
        int n = sub.Read(buf, 0, buf.Length);
        Assert.Equal(0, n);
        lock_.Dispose();
    }

    [Fact]
    public async Task ReadAsync_WithCancellationToken()
    {
        byte[] data = RandomNumberGenerator.GetBytes(1000);
        using var baseStream = new MemoryStream(data);
        var lock_ = new SemaphoreSlim(1, 1);
        using var sub = CreateFileSubStream(baseStream, 0, 1000, lock_);

        using var cts = new CancellationTokenSource();
        byte[] result = new byte[1000];
        await sub.ReadExactlyAsync(result, cts.Token);
        Assert.Equal(data, result);
        lock_.Dispose();
    }
}
