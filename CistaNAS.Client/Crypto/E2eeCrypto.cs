using System.Security.Cryptography;
using System.Text;

namespace CistaNAS.Client.Crypto;

/// <summary>
/// AES-256-GCM チャンク暗号化。サーバーの JS 実装とバイナリ互換。
/// </summary>
public static class E2eeCrypto
{
    private const int GcmNonceSize = 12;
    private const int GcmTagSize = 16;
    private const int SaltSize = 16;

    // ---- 鍵導出 ----

    public static byte[] DeriveKek(string username, string password, byte[] salt, int iterations)
    {
        byte[] userHash = SHA256.HashData(Encoding.UTF8.GetBytes(username));
        byte[] combinedSalt = new byte[userHash.Length + salt.Length];
        Buffer.BlockCopy(userHash, 0, combinedSalt, 0, userHash.Length);
        Buffer.BlockCopy(salt, 0, combinedSalt, userHash.Length, salt.Length);
        return Rfc2898DeriveBytes.Pbkdf2(password, combinedSalt, iterations, HashAlgorithmName.SHA256, 32);
    }

    public static byte[] GenerateMasterKey() => RandomNumberGenerator.GetBytes(32);

    public static byte[] GenerateFileSalt() => RandomNumberGenerator.GetBytes(SaltSize);

    // ---- マスターキー Wrap/Unwrap ----

    public static (byte[] Nonce, byte[] Ciphertext, byte[] Tag) WrapMasterKey(byte[] masterKey, byte[] kek)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(GcmNonceSize);
        byte[] ct = new byte[masterKey.Length];
        byte[] tag = new byte[GcmTagSize];
        using var gcm = new AesGcm(kek, GcmTagSize);
        gcm.Encrypt(nonce, masterKey, ct, tag);
        return (nonce, ct, tag);
    }

    public static byte[] UnwrapMasterKey(byte[] nonce, byte[] ct, byte[] tag, byte[] kek)
    {
        byte[] master = new byte[ct.Length];
        using var gcm = new AesGcm(kek, GcmTagSize);
        gcm.Decrypt(nonce, ct, tag, master);
        return master;
    }

    // ---- ファイル鍵導出 ----

    public static byte[] DeriveFileKey(byte[] masterKey, byte[] fileSalt)
    {
        return HkdfSha256(masterKey, fileSalt, Encoding.UTF8.GetBytes("cista-file-key"), 32);
    }

    // ---- チャンク暗号化 ----

    public static byte[] EncryptChunk(byte[] plaintext, byte[] fileKey, int chunkIndex, byte[] fileSalt, bool isFirstChunk)
    {
        byte[] nonce = DeriveChunkNonce(fileKey, chunkIndex);
        byte[] aad = BitConverter.GetBytes(chunkIndex);
        byte[] ct = new byte[plaintext.Length];
        byte[] tag = new byte[GcmTagSize];
        using var gcm = new AesGcm(fileKey, GcmTagSize);
        gcm.Encrypt(nonce, plaintext, ct, tag, aad);

        // フォーマット: [fileSalt (first chunk)] || [ciphertext] || [tag]
        int totalLen = (isFirstChunk ? SaltSize : 0) + ct.Length + tag.Length;
        byte[] result = new byte[totalLen];
        int offset = 0;
        if (isFirstChunk)
        {
            Buffer.BlockCopy(fileSalt, 0, result, 0, SaltSize);
            offset = SaltSize;
        }
        Buffer.BlockCopy(ct, 0, result, offset, ct.Length);
        Buffer.BlockCopy(tag, 0, result, offset + ct.Length, tag.Length);
        return result;
    }

    public static byte[] DecryptChunk(byte[] encData, byte[] fileKey, int chunkIndex, out byte[] fileSalt)
    {
        fileSalt = [];
        int offset = 0;

        if (chunkIndex == 0 && encData.Length > SaltSize + GcmTagSize)
        {
            fileSalt = new byte[SaltSize];
            Buffer.BlockCopy(encData, 0, fileSalt, 0, SaltSize);
            offset = SaltSize;
        }

        int ctLen = encData.Length - offset - GcmTagSize;
        byte[] ct = new byte[ctLen];
        byte[] tag = new byte[GcmTagSize];
        Buffer.BlockCopy(encData, offset, ct, 0, ctLen);
        Buffer.BlockCopy(encData, offset + ctLen, tag, 0, GcmTagSize);

        byte[] nonce = DeriveChunkNonce(fileKey, chunkIndex);
        byte[] aad = BitConverter.GetBytes(chunkIndex);
        byte[] plain = new byte[ctLen];
        using var gcm = new AesGcm(fileKey, GcmTagSize);
        gcm.Decrypt(nonce, ct, tag, plain, aad);
        return plain;
    }

    // ---- ファイル名暗号化 ----

    public static string EncryptFilename(string plainName, byte[] masterKey)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(GcmNonceSize);
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainName);
        byte[] ct = new byte[plainBytes.Length];
        byte[] tag = new byte[GcmTagSize];
        using var gcm = new AesGcm(masterKey, GcmTagSize);
        gcm.Encrypt(nonce, plainBytes, ct, tag);

        byte[] result = new byte[GcmNonceSize + ct.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, GcmNonceSize);
        Buffer.BlockCopy(ct, 0, result, GcmNonceSize, ct.Length);
        Buffer.BlockCopy(tag, 0, result, GcmNonceSize + ct.Length, tag.Length);
        return Convert.ToBase64String(result);
    }

    public static string DecryptFilename(string encBase64, byte[] masterKey)
    {
        byte[] raw = Convert.FromBase64String(encBase64);
        byte[] nonce = raw[..GcmNonceSize];
        byte[] ct = raw[GcmNonceSize..^GcmTagSize];
        byte[] tag = raw[^GcmTagSize..];
        byte[] plain = new byte[ct.Length];
        using var gcm = new AesGcm(masterKey, GcmTagSize);
        gcm.Decrypt(nonce, ct, tag, plain);
        return Encoding.UTF8.GetString(plain);
    }

    // ---- 内部ヘルパー ----

    private static byte[] DeriveChunkNonce(byte[] fileKey, int chunkIndex)
    {
        byte[] indexBytes = BitConverter.GetBytes(chunkIndex);
        byte[] mac = HMACSHA256.HashData(fileKey, indexBytes);
        return mac[..GcmNonceSize];
    }

    private static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int outputLength)
    {
        // HKDF-Extract
        byte[] prk = HMACSHA256.HashData(salt, ikm);

        // HKDF-Expand
        byte[] result = new byte[outputLength];
        byte[] t = [];
        int offset = 0;
        for (byte counter = 1; offset < outputLength; counter++)
        {
            byte[] input = new byte[t.Length + info.Length + 1];
            Buffer.BlockCopy(t, 0, input, 0, t.Length);
            Buffer.BlockCopy(info, 0, input, t.Length, info.Length);
            input[^1] = counter;
            t = HMACSHA256.HashData(prk, input);
            int copyLen = Math.Min(t.Length, outputLength - offset);
            Buffer.BlockCopy(t, 0, result, offset, copyLen);
            offset += copyLen;
        }
        return result;
    }
}
