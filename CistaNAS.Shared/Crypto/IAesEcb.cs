namespace CistaNAS.Shared.Crypto;

/// <summary>
/// AES-ECB ブロック暗号の抽象化。
/// ネイティブ (System.Security.Cryptography.Aes) と
/// Managed (WASM 用 pure C#) の両実装を透過的に切替える。
/// </summary>
internal interface IAesEcb : IDisposable
{
    /// <summary>1 ブロック (16 バイト) を暗号化する。</summary>
    void EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output);

    /// <summary>1 ブロック (16 バイト) を復号する。</summary>
    void DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output);
}
