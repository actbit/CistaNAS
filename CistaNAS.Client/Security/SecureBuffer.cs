using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CistaNAS.Client.Security;

/// <summary>
/// 機密データ（暗号鍵等）の byte[] をページング退避から保護し、確実にゼロクリアする。
/// <para>GCHandle.Pinned で GC 移動を防ぎつつ VirtualLock で RAM にロック（スワップファイルへの漏洩防止）。
/// Dispose で VirtualUnlock + ZeroMemory + ハンドル解放。</para>
/// <para>CistaNAS.Client は net10.0-windows 専用のため OS 分岐不要。</para>
/// </summary>
public sealed class SecureBuffer : IDisposable
{
    private byte[] _buffer;
    private GCHandle _handle;
    private bool _disposed;

    public SecureBuffer(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        _buffer = data;
        _handle = GCHandle.Alloc(_buffer, GCHandleType.Pinned);
        // ページング退避防止。権限不足/上限で失敗しうるがベストエフォート（ゼロクリアは Dispose で確実）。
        VirtualLock(_handle.AddrOfPinnedObject(), (UIntPtr)_buffer.Length);
    }

    /// <summary>E2eeCrypto 等の byte[] 引数へ渡すための配列。ピン固定済みでアドレスは不変。</summary>
    public byte[] Buffer
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer;
        }
    }

    public Span<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer;
        }
    }

    public int Length => _buffer.Length;

    public void Dispose()
    {
        if (_disposed) return;
        VirtualUnlock(_handle.AddrOfPinnedObject(), (UIntPtr)_buffer.Length);
        CryptographicOperations.ZeroMemory(_buffer);
        _handle.Free();
        _disposed = true;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualLock(IntPtr address, UIntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualUnlock(IntPtr address, UIntPtr size);
}
