namespace CistaNAS.Client.Crypto;

/// <summary>暗号化アルゴリズム。</summary>
public enum CipherAlgorithm
{
    /// <summary>AES-256-XTS（IEEE 1619）</summary>
    Aes256Xts,

    /// <summary>ChaCha20（RFC 7539）</summary>
    ChaCha20,
}

/// <summary>暗号化アルゴリズム拡張メソッド。</summary>
public static class CipherAlgorithmExtensions
{
    /// <summary>文字列表現を取得。</summary>
    public static string ToQueryString(this CipherAlgorithm algorithm) => algorithm switch
    {
        CipherAlgorithm.Aes256Xts => "aes-256-xts",
        CipherAlgorithm.ChaCha20 => "chacha20",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
    };

    /// <summary>文字列から解析。</summary>
    public static CipherAlgorithm ParseCipherAlgorithm(string value) => value.ToLowerInvariant() switch
    {
        "aes-256-xts" => CipherAlgorithm.Aes256Xts,
        "chacha20" or "chacha20-xts" => CipherAlgorithm.ChaCha20,
        _ => throw new ArgumentException($"不明な暗号化アルゴリズム: {value}")
    };

    /// <summary>キーサイズ（バイト）を取得。</summary>
    public static int GetKeySize(this CipherAlgorithm algorithm) => algorithm switch
    {
        CipherAlgorithm.Aes256Xts => 64,  // K1 || K2 (32 + 32)
        CipherAlgorithm.ChaCha20 => 32,  // 256-bit
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
    };
}
