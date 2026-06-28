namespace CistaNAS.Web.Services;

/// <summary>
/// async-friendly なファイル単位の読み書きゲート。
/// 複数の並行読み取りを許可し、書き込みは全読み取りの完了を待機する。
/// <see cref="ReaderWriterLockSlim"/> と異なりスレッドアフィンではないため、
/// async/await で別スレッドに継続しても正しく動作する。
/// </summary>
internal sealed class AsyncFileGate : IDisposable
{
    private int _readerCount;
    private int _writerWaiting; // ライター待機中フラグ（スタベーション防止）
    private readonly SemaphoreSlim _gate = new(1, 1);
    // ライターに「全リーダー完了」を即時通知する TCS
    private TaskCompletionSource<object?>? _readersCompletedTcs;
    private bool _disposed;

    /// <summary>読み取りロックを取得。並行読み取り可。戻り値の IDisposable で解放。</summary>
    public async Task<IDisposable> EnterReadAsync(CancellationToken ct)
    {
        // ライター待機中は新規リーダーの入場をブロック（スタベーション防止）
        while (true)
        {
            await _gate.WaitAsync(ct);
            if (Volatile.Read(ref _writerWaiting) == 0)
            {
                _readerCount++;
                _gate.Release();
                return new ReadReleaser(this);
            }
            _gate.Release();
            await Task.Delay(TimeSpan.FromMilliseconds(10), ct);
        }
    }

    /// <summary>書き込みロックを取得。全読み取りの完了を即時通知で待機。戻り値の IDisposable で解放。</summary>
    public async Task<IDisposable> EnterWriteAsync(CancellationToken ct)
    {
        // ライターは _gate を取得したまま全リーダーの完了を待つ（ライター間を直列化）。
        // かつて待機前に _gate を Release していたため、複数ライターが同時に待機して
        // _readersCompletedTcs を上書きし、先のライターが永久スタックするハングがあった。
        // 待機中も _gate を保持することで、2 番目以降のライターは _gate 待ちになり上書きを防ぐ。
        bool writerWaitingSet = false;
        bool gateHeld = false;
        try
        {
            await _gate.WaitAsync(ct);
            gateHeld = true;
            Volatile.Write(ref _writerWaiting, 1);
            writerWaitingSet = true;

            while (Volatile.Read(ref _readerCount) > 0)
            {
                // TCS を作成（_gate 保持中）してから二重チェック
                _readersCompletedTcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
                if (Volatile.Read(ref _readerCount) == 0)
                {
                    // 二重チェック: 待機中に全リーダーが完了 → 即時突破
                    _readersCompletedTcs = null;
                    break;
                }
                try
                {
                    using var reg = ct.Register(static state => ((TaskCompletionSource<object?>)state!).TrySetCanceled(), _readersCompletedTcs);
                    await _readersCompletedTcs.Task;
                }
                catch
                {
                    // キャンセル時: writerWaiting をリセットし _gate を解放（待機中も保持しているため）
                    _readersCompletedTcs = null;
                    Volatile.Write(ref _writerWaiting, 0);
                    writerWaitingSet = false;
                    _gate.Release();
                    gateHeld = false;
                    throw;
                }
            }
            _readersCompletedTcs = null;
            // _gate の所有権を WriteReleaser に移譲（ExitWrite で解放）
            gateHeld = false;
            return new WriteReleaser(this);
        }
        catch
        {
            if (writerWaitingSet) Volatile.Write(ref _writerWaiting, 0);
            if (gateHeld) _gate.Release();
            throw;
        }
    }

    private void ExitRead()
    {
        if (Interlocked.Decrement(ref _readerCount) == 0 && Volatile.Read(ref _writerWaiting) == 1)
        {
            // 最後のリーダーが抜けた → ライターに即時通知
            _readersCompletedTcs?.TrySetResult(result: null!);
        }
    }

    private void ExitWrite()
    {
        Volatile.Write(ref _writerWaiting, 0);
        _gate.Release();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _readersCompletedTcs?.TrySetCanceled();
        _gate.Dispose();
    }

    private sealed class ReadReleaser(AsyncFileGate gate) : IDisposable
    {
        public void Dispose() => gate.ExitRead();
    }

    private sealed class WriteReleaser(AsyncFileGate gate) : IDisposable
    {
        public void Dispose() => gate.ExitWrite();
    }
}
