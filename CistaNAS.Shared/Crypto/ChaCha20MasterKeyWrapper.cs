namespace CistaNAS.Shared.Crypto;

/// <summary>
/// ChaCha20-Poly1305 でマスターキーをラップ/アンラップする実装。
/// </summary>
public sealed class ChaCha20MasterKeyWrapper : IMasterKeyWrapper
{
    public const int NonceSize = 12;
    public const int TagSize = 16;

    public string AlgorithmName => "chacha20-poly1305";

    public (byte[] Nonce, byte[] Ciphertext, byte[] Tag) Wrap(byte[] masterKey, byte[] kek)
    {
        byte[] nonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(NonceSize);
        return ChaCha20Poly1305.Encrypt(masterKey, kek, nonce);
    }

    public byte[] Unwrap(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] kek)
    {
        return ChaCha20Poly1305.Decrypt(ciphertext, tag, nonce, kek);
    }
}
