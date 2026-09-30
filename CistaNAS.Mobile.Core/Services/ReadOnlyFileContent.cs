using System.Security.Cryptography;

namespace CistaNAS.Mobile.Core.Services;

/// <summary>読み取り位置を指定できるファイル内容。復号データはRAM内でだけ扱う。</summary>
public abstract class ReadOnlyFileContent : IDisposable
{
    public const int MaxReadBytes = 64 * 1024;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly CancellationTokenSource _lifetime;
    private int _disposed;
    private int _cleared;

    protected ReadOnlyFileContent(string name, long length, CancellationToken sessionCancellation)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        Name = name;
        Length = length;
        _lifetime = CancellationTokenSource.CreateLinkedTokenSource(sessionCancellation);
        Cancellation = _lifetime.Token;
    }

    public string Name { get; }
    public string MimeType => FileCategoryService.GetMimeType(Name);
    public long Length { get; }
    public CancellationToken Cancellation { get; }

    public async ValueTask<int> ReadAsync(long offset, Memory<byte> destination, CancellationToken ct = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(Cancellation, ct);
        await _gate.WaitAsync(linked.Token).ConfigureAwait(false);
        int count = 0;
        try
        {
            linked.Token.ThrowIfCancellationRequested();
            if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(GetType().Name);
            count = (int)Math.Min(Math.Min(destination.Length, MaxReadBytes), Math.Max(0, Length - offset));
            if (count == 0) return 0;
            int read = await ReadCoreAsync(offset, destination[..count], linked.Token).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            if (read != count) throw new EndOfStreamException("ファイルの読み取りが途中で終了しました。");
            return read;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(destination.Span[..count]);
            throw;
        }
        finally
        {
            if (Volatile.Read(ref _disposed) != 0) ClearOnce();
            _gate.Release();
        }
    }

    protected abstract ValueTask<int> ReadCoreAsync(long offset, Memory<byte> destination, CancellationToken ct);
    protected virtual void ClearBuffers() { }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _lifetime.Cancel();
        // 401通知は読み取り処理の中から届くため、使用中のgateを待たない。
        // 使用中ならReadAsyncのfinallyが消去し、未使用ならここで消去する。
        if (_gate.Wait(0))
        {
            try { ClearOnce(); }
            finally { _gate.Release(); }
        }
        _lifetime.Dispose();
    }

    private void ClearOnce() { if (Interlocked.Exchange(ref _cleared, 1) == 0) ClearBuffers(); }
}
