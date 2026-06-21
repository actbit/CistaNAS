using System.Security.Cryptography;

namespace CistaNAS.Shared.Crypto;

/// <summary>
/// AES-256-GCM でマスターキーをラップ/アンラップする実装。
/// </summary>
public sealed class AesGcmMasterKeyWrapper : IMasterKeyWrapper
{
    public const int NonceSize = 12;
    public const int TagSize = 16;

    public string AlgorithmName => "aes-256-gcm";

    public (byte[] Nonce, byte[] Ciphertext, byte[] Tag) Wrap(byte[] masterKey, byte[] kek)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] ciphertext = new byte[masterKey.Length];
        byte[] tag = new byte[TagSize];

        using var gcm = new AesGcm(kek, TagSize);
        gcm.Encrypt(nonce, masterKey, ciphertext, tag);

        return (nonce, ciphertext, tag);
    }

    public byte[] Unwrap(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] kek)
    {
        byte[] masterKey = new byte[ciphertext.Length];

        using var gcm = new AesGcm(kek, TagSize);
        gcm.Decrypt(nonce, ciphertext, tag, masterKey);

        return masterKey;
    }
}
