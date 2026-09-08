using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CistaNAS.Mobile.Core.Security;

/// <summary>
/// 機密データ (鍵・パスワード) をメモリ上で保護するバッファ。
/// pin してから <see cref="CryptographicOperations.ZeroMemory"/> で解放時にゼロクリアする。
/// (Desktop Client 版の VirtualLock は Windows 専用のため、モバイルでは pin + ゼロクリアのみ。)
/// </summary>
public sealed class SecureBuffer : IDisposable
{
    private byte[]? _data;
    private GCHandle _handle;
    private bool _disposed;

    public SecureBuffer(int length)
    {
        if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
        _data = new byte[length];
        _handle = GCHandle.Alloc(_data, GCHandleType.Pinned);
    }

    public SecureBuffer(byte[] data)
    {
        _data = new byte[data.Length];
        Array.Copy(data, _data, data.Length);
        _handle = GCHandle.Alloc(_data, GCHandleType.Pinned);
    }

    /// <summary>保護されたデータ。解放後のアクセスは InvalidOperationException。</summary>
    public byte[] Data =>
        _disposed || _data is null
            ? throw new InvalidOperationException("SecureBuffer は既に解放されています。")
            : _data;

    public int Length => _disposed ? 0 : _data?.Length ?? 0;

    /// <summary>テスト用: 解放後にゼロクリア済みの内部バッファを観察する。</summary>
    internal byte[]? PeekRawForTest() => _disposed ? _data : null;

    /// <summary>内容をゼロで上書きしてから pin を解除する。冪等。</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_data is not null)
        {
            CryptographicOperations.ZeroMemory(_data);
        }
        if (_handle.IsAllocated)
        {
            _handle.Free();
        }
    }
}
