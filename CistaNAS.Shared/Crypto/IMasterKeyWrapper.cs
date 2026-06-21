namespace CistaNAS.Shared.Crypto;

/// <summary>
/// マスターキーのラップ/アンラップを行うストラテジインターフェース。
/// </summary>
public interface IMasterKeyWrapper
{
    /// <summary>アルゴリズム名。</summary>
    string AlgorithmName { get; }

    /// <summary>マスターキーをラップする。</summary>
    (byte[] Nonce, byte[] Ciphertext, byte[] Tag) Wrap(byte[] masterKey, byte[] kek);

    /// <summary>マスターキーをアンラップする。</summary>
    byte[] Unwrap(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] kek);
}
