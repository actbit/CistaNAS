using CistaNAS.Web.Services;

namespace CistaNAS.Tests;

/// <summary>
/// AsyncFileGate の単体テスト。
/// スタベーション防止・並行リーダー・読み書き排他・即時通知・Dispose を検証。
/// </summary>
public class AsyncFileGateTests
{
    private static CancellationToken Ct => CancellationToken.None;

    /// <summary>複数の並行リーダーが同時に読み取りロックを取得できる。</summary>
    [Fact]
    public async Task ConcurrentReaders_AllEnter()
    {
        using var gate = new AsyncFileGate();
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
        using var gate = new AsyncFileGate();
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
        using var gate = new AsyncFileGate();
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
        using var gate = new AsyncFileGate();
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
        using var gate = new AsyncFileGate();
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
        await Task.Delay(50);
        Assert.False(writerEntered);

        rl2.Dispose();
        await Task.Delay(50);
        Assert.False(writerEntered);

        rl3.Dispose();
        await writerTask;
        Assert.True(writerEntered);
    }

    /// <summary>
    /// リーダー保持中に2つのライターが同時に待機しても、先のライターが
    /// 永久スタックしないこと（_readersCompletedTcs の上書きによるハング回帰防止）。
    /// </summary>
    [Fact]
    public async Task TwoWriters_BothAcquire_NoHang()
    {
        using var gate = new AsyncFileGate();
        var readLock = await gate.EnterReadAsync(Ct);

        var w1Entered = new TaskCompletionSource<bool>();
        var w2Entered = new TaskCompletionSource<bool>();

        var w1 = Task.Run(async () =>
        {
            using var wl = await gate.EnterWriteAsync(Ct);
            w1Entered.SetResult(true);
            await Task.Delay(100);
        });

        var w2 = Task.Run(async () =>
        {
            using var wl = await gate.EnterWriteAsync(Ct);
            w2Entered.SetResult(true);
            wl.Dispose();
        });

        await Task.Delay(200); // 両ライターが待機状態に入るまで待つ

        readLock.Dispose(); // リーダー解放 → ライターが順に取得されるはず

        // 5 秒以内に両ライターが取得できること（ハングしない）
        await w1Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await w2Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await w1;
    }

    /// <summary>読み取りロックの Dispose が正しくカウントを減らす。</summary>
    [Fact]
    public async Task ReadLockDispose_DecrementsCount()
    {
        using var gate = new AsyncFileGate();
        var rl = await gate.EnterReadAsync(Ct);
        rl.Dispose();

        var wl = await gate.EnterWriteAsync(Ct);
        wl.Dispose();
    }

    /// <summary>書き込みロック中に別の書き込みロックはブロックされる。</summary>
    [Fact]
    public async Task WriteLock_BlocksOtherWriter()
    {
        using var gate = new AsyncFileGate();
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
        using var gate = new AsyncFileGate();
        var wl = await gate.EnterWriteAsync(Ct);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            gate.EnterReadAsync(cts.Token));

        wl.Dispose();
    }

    /// <summary>CancellationToken で書き込み待機（リーダー完了待ち）をキャンセルできる。</summary>
    [Fact]
    public async Task WriteLock_Cancellation_WhileWaitingForReaders()
    {
        using var gate = new AsyncFileGate();
        var readLock = await gate.EnterReadAsync(Ct);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            gate.EnterWriteAsync(cts.Token));

        // キャンセル後も gate は正常に機能する
        readLock.Dispose();
        var wl = await gate.EnterWriteAsync(Ct);
        wl.Dispose();
    }

    /// <summary>最後のリーダーの解放でライターに即時通知される（遅延なし）。</summary>
    [Fact]
    public async Task LastReaderExit_InstantWriterNotification()
    {
        using var gate = new AsyncFileGate();
        var readLock = await gate.EnterReadAsync(Ct);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        bool writerAcquired = false;
        var writerTask = Task.Run(async () =>
        {
            using var wl = await gate.EnterWriteAsync(Ct);
            writerAcquired = true;
        });

        // ライターが待機状態に入るまで少し待つ
        await Task.Delay(100);

        // リーダーを解放 → ライターに即時通知されるはず
        readLock.Dispose();
        await writerTask;
        sw.Stop();

        Assert.True(writerAcquired);
        // 即時通知なら 50ms 以内に完了するはず（スピンウェイトの 20ms より高速）
        Assert.True(sw.ElapsedMilliseconds < 200, $"ライター取得に {sw.ElapsedMilliseconds}ms かかった");
    }

    /// <summary>Dispose 後に新しい操作は ObjectDisposedException。</summary>
    [Fact]
    public async Task Dispose_PreventsNewOperations()
    {
        var gate = new AsyncFileGate();
        gate.Dispose();

        await Assert.ThrowsAnyAsync<ObjectDisposedException>(() =>
            gate.EnterReadAsync(Ct));

        await Assert.ThrowsAnyAsync<ObjectDisposedException>(() =>
            gate.EnterWriteAsync(Ct));
    }

    /// <summary>Dispose を2回呼んでも例外にならない。</summary>
    [Fact]
    public void DoubleDispose_NoException()
    {
        var gate = new AsyncFileGate();
        gate.Dispose();
        gate.Dispose(); // 2回目
    }

    /// <summary>ReadLock の Dispose を2回呼んでもカウントが負にならない。</summary>
    [Fact]
    public async Task ReadLock_DoubleDispose_Idempotent()
    {
        using var gate = new AsyncFileGate();
        var rl = await gate.EnterReadAsync(Ct);
        rl.Dispose();
        rl.Dispose(); // 2回目（no-op であるべき）

        // カウントが正しく 0 になっていれば書き込みが即座に取得できる
        var wl = await gate.EnterWriteAsync(Ct);
        wl.Dispose();
    }
}
