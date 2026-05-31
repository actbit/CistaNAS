using CistaNAS.Web.Services;

namespace CistaNAS.Tests;

/// <summary>
/// AsyncFileGate の単体テスト。
/// スタベーション防止・並行リーダー・読み書き排他を検証。
/// </summary>
public class AsyncFileGateTests
{
    private static CancellationToken Ct => CancellationToken.None;

    /// <summary>複数の並行リーダーが同時に読み取りロックを取得できる。</summary>
    [Fact]
    public async Task ConcurrentReaders_AllEnter()
    {
        var gate = new AsyncFileGate();
        var locks = new List<IDisposable>();

        for (int i = 0; i < 5; i++)
            locks.Add(await gate.EnterReadAsync(Ct));

        Assert.Equal(5, locks.Count);

        foreach (var l in locks)
            l.Dispose();
    }

    /// <summary>書き込みロック中は読み取りがブロックされる。</summary>
    [Fact]
    public async Task WriteLock_BlocksReaders()
    {
        var gate = new AsyncFileGate();
        var writeLock = await gate.EnterWriteAsync(Ct);

        bool readerEntered = false;
        var readerTask = Task.Run(async () =>
        {
            using var rl = await gate.EnterReadAsync(Ct);
            readerEntered = true;
        });

        await Task.Delay(200);
        Assert.False(readerEntered);

        writeLock.Dispose();
        await readerTask;
        Assert.True(readerEntered);
    }

    /// <summary>読み取りロック中は書き込みがブロックされる。</summary>
    [Fact]
    public async Task ReadLock_BlocksWriter()
    {
        var gate = new AsyncFileGate();
        var readLock = await gate.EnterReadAsync(Ct);

        bool writerEntered = false;
        var writerTask = Task.Run(async () =>
        {
            using var wl = await gate.EnterWriteAsync(Ct);
            writerEntered = true;
        });

        await Task.Delay(200);
        Assert.False(writerEntered);

        readLock.Dispose();
        await writerTask;
        Assert.True(writerEntered);
    }

    /// <summary>ライター待機中は新しいリーダーが入場できない（スタベーション防止）。</summary>
    [Fact]
    public async Task WriterWaiting_BlockNewReaders()
    {
        var gate = new AsyncFileGate();
        var readLock1 = await gate.EnterReadAsync(Ct);

        bool writerAcquired = false;
        var writerTask = Task.Run(async () =>
        {
            using var wl = await gate.EnterWriteAsync(Ct);
            writerAcquired = true;
        });

        await Task.Delay(200);
        Assert.False(writerAcquired);

        bool newReaderEntered = false;
        var newReaderTask = Task.Run(async () =>
        {
            using var rl = await gate.EnterReadAsync(Ct);
            newReaderEntered = true;
        });

        await Task.Delay(200);
        Assert.False(newReaderEntered);

        readLock1.Dispose();
        await writerTask;
        Assert.True(writerAcquired);

        await newReaderTask;
        Assert.True(newReaderEntered);
    }

    /// <summary>複数リーダーの解放後にライターが取得できる。</summary>
    [Fact]
    public async Task MultipleReaders_WriterWaitsForAll()
    {
        var gate = new AsyncFileGate();
        var rl1 = await gate.EnterReadAsync(Ct);
        var rl2 = await gate.EnterReadAsync(Ct);
        var rl3 = await gate.EnterReadAsync(Ct);

        bool writerEntered = false;
        var writerTask = Task.Run(async () =>
        {
            using var wl = await gate.EnterWriteAsync(Ct);
            writerEntered = true;
        });

        await Task.Delay(200);
        Assert.False(writerEntered);

        rl1.Dispose();
        await Task.Delay(100);
        Assert.False(writerEntered);

        rl2.Dispose();
        await Task.Delay(100);
        Assert.False(writerEntered);

        rl3.Dispose();
        await writerTask;
        Assert.True(writerEntered);
    }

    /// <summary>読み取りロックの Dispose が正しくカウントを減らす。</summary>
    [Fact]
    public async Task ReadLockDispose_DecrementsCount()
    {
        var gate = new AsyncFileGate();
        var rl = await gate.EnterReadAsync(Ct);
        rl.Dispose();

        // 書き込みロックが即座に取得できるはず
        var wl = await gate.EnterWriteAsync(Ct);
        wl.Dispose();
    }

    /// <summary>書き込みロック中に別の書き込みロックはブロックされる。</summary>
    [Fact]
    public async Task WriteLock_BlocksOtherWriter()
    {
        var gate = new AsyncFileGate();
        var wl1 = await gate.EnterWriteAsync(Ct);

        bool wl2Acquired = false;
        var writerTask = Task.Run(async () =>
        {
            using var wl = await gate.EnterWriteAsync(Ct);
            wl2Acquired = true;
        });

        await Task.Delay(200);
        Assert.False(wl2Acquired);

        wl1.Dispose();
        await writerTask;
        Assert.True(wl2Acquired);
    }

    /// <summary>CancellationToken で読み取り待機をキャンセルできる。</summary>
    [Fact]
    public async Task ReadLock_Cancellation()
    {
        var gate = new AsyncFileGate();
        var wl = await gate.EnterWriteAsync(Ct);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            gate.EnterReadAsync(cts.Token));

        wl.Dispose();
    }
}
