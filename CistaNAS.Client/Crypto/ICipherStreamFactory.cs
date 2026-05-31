namespace CistaNAS.Client.Crypto;

/// <summary>暗号化ストリームファクトリ。</summary>
public interface ICipherStreamFactory
{
    /// <summary>暗号化ストリームを作成。</summary>
    /// <param name="baseStream">基底ストリーム。</param>
    /// <param name="masterKey">マスターキー。</param>
    /// <param name="algorithm">暗号化アルゴリズム。</param>
    /// <param name="logicalLength">論理長。</param>
    /// <param name="writable">書き込み可能かどうか。</param>
    /// <returns>暗号化ストリーム。</returns>
    Stream CreateCipherStream(
        Stream baseStream,
        byte[] masterKey,
        CipherAlgorithm algorithm,
        long logicalLength,
        bool writable = true);
}

/// <summary>デフォルトの暗号化ストリームファクトリ。</summary>
public sealed class DefaultCipherStreamFactory : ICipherStreamFactory
{
    public Stream CreateCipherStream(
        Stream baseStream,
        byte[] masterKey,
        CipherAlgorithm algorithm,
        long logicalLength,
        bool writable = true)
    {
        return algorithm switch
        {
            CipherAlgorithm.Aes256Xts => AesXtsStream.CreateAesXtsStream(baseStream, masterKey, logicalLength, writable),
            CipherAlgorithm.ChaCha20 => CreateChaCha20Stream(baseStream, masterKey, logicalLength, writable),
            _ => throw new ArgumentException($"サポートされていない暗号化アルゴリズム: {algorithm}")
        };
    }

    /// <summary>ChaCha20 ストリームを作成。</summary>
    private static Stream CreateChaCha20Stream(
        Stream baseStream,
        byte[] masterKey,
        long logicalLength,
        bool writable)
    {
        // ChaCha20 は 32 バイトキー
        if (masterKey.Length != 32)
            throw new ArgumentException($"ChaCha20 鍵長は 32 バイトである必要があります。");

        // ノンス生成（固定値を使用）
        byte[] nonce = new byte[12];
        Buffer.BlockCopy(masterKey, 0, nonce, 0, 12);

        return new ChaCha20Stream(baseStream, masterKey, nonce, logicalLength, writable);
    }
}
