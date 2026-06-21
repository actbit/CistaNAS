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
        // 入口でキャンセル要求をチェックし、_writerWaiting を残さないように。
        // 戻り時の例外パスでも _writerWaiting を必ず 0 に戻す。
        bool writerWaitingSet = false;
        try
        {
            await _gate.WaitAsync(ct);
            Volatile.Write(ref _writerWaiting, 1);
            writerWaitingSet = true;
            while (_readerCount > 0)
            {
                // TCS を作成（gate 保持中）してから二重チェック
                _readersCompletedTcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
                if (Volatile.Read(ref _readerCount) == 0)
                {
                    // 二重チェック: 待機中に全リーダーが完了 → 即時突破
                    _readersCompletedTcs = null;
                    break;
                }
                _gate.Release();
                try
                {
                    using var reg = ct.Register(static state => ((TaskCompletionSource<object?>)state!).TrySetCanceled(), _readersCompletedTcs);
                    await _readersCompletedTcs.Task;
                }
                catch
                {
                    // キャンセル時は _writerWaiting をリセット
                    // 注: gate は既に while ループ内で Release 済み。再 Release しないこと。
                    Volatile.Write(ref _writerWaiting, 0);
                    writerWaitingSet = false;
                    _readersCompletedTcs = null;
                    throw;
                }
                await _gate.WaitAsync(ct);
            }
            _readersCompletedTcs = null;
            // _gate を保持したまま返す → ExitWrite で解放
            return new WriteReleaser(this);
        }
        catch
        {
            // 外側のリトライ中の _gate.WaitAsync(ct) がキャンセルされた場合や
            // 入口で即時キャンセルされた場合に _writerWaiting を必ずリセットする。
            if (writerWaitingSet)
            {
                Volatile.Write(ref _writerWaiting, 0);
                writerWaitingSet = false;
            }
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
