using System.Security.Cryptography;

namespace CistaNAS.Shared.Crypto;

/// <summary>
/// System.Security.Cryptography.Aes を使用した AES-ECB 実装。
/// ネイティブ環境 (Windows/Linux/macOS) で使用。ハードウェア AES-NI が利用可能。
/// </summary>
internal sealed class SystemAesEcb : IAesEcb
{
    private readonly Aes _aes;
    private readonly ICryptoTransform? _encryptor;
    private readonly ICryptoTransform? _decryptor;
    private bool _disposed;

    /// <summary>
    /// AES-256-ECB を初期化。
    /// <paramref name="encrypt"/> が null の場合は暗号化・復号両対応。
    /// </summary>
    public SystemAesEcb(ReadOnlySpan<byte> key, bool? encrypt)
    {
        _aes = Aes.Create();
        _aes.Mode = CipherMode.ECB;
        _aes.Padding = PaddingMode.None;
        _aes.Key = key.ToArray();

        if (encrypt == null || encrypt == true)
            _encryptor = _aes.CreateEncryptor();
        if (encrypt == null || encrypt == false)
            _decryptor = _aes.CreateDecryptor();
    }

    public void EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_encryptor is null) throw new InvalidOperationException("暗号化は有効化されていません。");
        byte[] inBuf = input.ToArray();
        byte[] outBuf = new byte[16];
        _encryptor.TransformBlock(inBuf, 0, 16, outBuf, 0);
        outBuf.AsSpan().CopyTo(output);
    }

    public void DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_decryptor is null) throw new InvalidOperationException("復号は有効化されていません。");
        byte[] inBuf = input.ToArray();
        byte[] outBuf = new byte[16];
        _decryptor.TransformBlock(inBuf, 0, 16, outBuf, 0);
        outBuf.AsSpan().CopyTo(output);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _encryptor?.Dispose();
        _decryptor?.Dispose();
        CryptographicOperations.ZeroMemory(_aes.Key);
        _aes.Dispose();
    }
}
