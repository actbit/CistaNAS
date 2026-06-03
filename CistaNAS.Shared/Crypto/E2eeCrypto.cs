using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace CistaNAS.Shared.Crypto;

/// <summary>
/// E2EE チャンク暗号化。AES-256-GCM および ChaCha20-Poly1305 をサポート。
/// </summary>
public static class E2eeCrypto
{
    private const int GcmNonceSize = 12;
    private const int GcmTagSize = 16;
    private const int SaltSize = 16;
    private const int MasterKeySize = 32;

    // ---- 鍵導出 ----

    public static byte[] DeriveKek(string username, string password, byte[] salt, int iterations)
    {
        byte[] userHash = SHA256.HashData(Encoding.UTF8.GetBytes(username));
        byte[] combinedSalt = new byte[userHash.Length + salt.Length];
        Buffer.BlockCopy(userHash, 0, combinedSalt, 0, userHash.Length);
        Buffer.BlockCopy(salt, 0, combinedSalt, userHash.Length, salt.Length);
        return Rfc2898DeriveBytes.Pbkdf2(password, combinedSalt, iterations, HashAlgorithmName.SHA256, 32);
    }

    public static byte[] GenerateMasterKey() => RandomNumberGenerator.GetBytes(MasterKeySize);

    public static byte[] GenerateFileSalt() => RandomNumberGenerator.GetBytes(SaltSize);

    // ---- マスターキー Wrap/Unwrap ----

    /// <summary>マスターキーをラップする。</summary>
    public static (byte[] Nonce, byte[] Ciphertext, byte[] Tag) WrapMasterKey(byte[] masterKey, byte[] kek, string algorithm = "aes-256-gcm")
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(GcmNonceSize);

        switch (algorithm.ToLowerInvariant())
        {
            case "aes-256-gcm":
                return WrapMasterKeyAesGcm(masterKey, kek, nonce);

            case "chacha20-poly1305":
                return WrapMasterKeyChaCha20(masterKey, kek, nonce);

            default:
                throw new ArgumentException($"サポートされていないラップアルゴリズム: {algorithm}");
        }
    }

    /// <summary>AES-256-GCM でマスターキーをラップ。</summary>
    private static (byte[] Nonce, byte[] Ciphertext, byte[] Tag) WrapMasterKeyAesGcm(byte[] masterKey, byte[] kek, byte[] nonce)
    {
        byte[] ct = new byte[masterKey.Length];
        byte[] tag = new byte[GcmTagSize];
        using var gcm = new AesGcm(kek, GcmTagSize);
        gcm.Encrypt(nonce, masterKey, ct, tag);
        return (nonce, ct, tag);
    }

    /// <summary>ChaCha20-Poly1305 でマスターキーをラップ。</summary>
    private static (byte[] Nonce, byte[] Ciphertext, byte[] Tag) WrapMasterKeyChaCha20(byte[] masterKey, byte[] kek, byte[] nonce)
    {
        return ChaCha20Poly1305.Encrypt(masterKey, kek, nonce);
    }

    /// <summary>マスターキーをアンラップする。</summary>
    public static byte[] UnwrapMasterKey(byte[] nonce, byte[] ct, byte[] tag, byte[] kek, string algorithm = "aes-256-gcm")
    {
        switch (algorithm.ToLowerInvariant())
        {
            case "aes-256-gcm":
                return UnwrapMasterKeyAesGcm(nonce, ct, tag, kek);

            case "chacha20-poly1305":
                return UnwrapMasterKeyChaCha20(nonce, ct, tag, kek);

            default:
                throw new ArgumentException($"サポートされていないラップアルゴリズム: {algorithm}");
        }
    }

    /// <summary>AES-256-GCM でマスターキーをアンラップ。</summary>
    private static byte[] UnwrapMasterKeyAesGcm(byte[] nonce, byte[] ct, byte[] tag, byte[] kek)
    {
        byte[] master = new byte[ct.Length];
        using var gcm = new AesGcm(kek, GcmTagSize);
        gcm.Decrypt(nonce, ct, tag, master);
        return master;
    }

    /// <summary>ChaCha20-Poly1305 でマスターキーをアンラップ。</summary>
    private static byte[] UnwrapMasterKeyChaCha20(byte[] nonce, byte[] ct, byte[] tag, byte[] kek)
    {
        return ChaCha20Poly1305.Decrypt(ct, tag, nonce, kek);
    }

    // ---- ファイル鍵導出 ----

    public static byte[] DeriveFileKey(byte[] masterKey, byte[] fileSalt)
    {
        return HkdfSha256(masterKey, fileSalt, Encoding.UTF8.GetBytes("cista-file-key"), 32);
    }

    // ---- チャンク暗号化 ----

    /// <summary>チャンクを暗号化する。</summary>
    public static byte[] EncryptChunk(byte[] plaintext, byte[] fileKey, int chunkIndex, byte[] fileSalt, bool isFirstChunk, string algorithm = "aes-256-gcm")
    {
        switch (algorithm.ToLowerInvariant())
        {
            case "aes-256-gcm":
                return EncryptChunkAesGcm(plaintext, fileKey, chunkIndex, fileSalt, isFirstChunk);

            case "chacha20-poly1305":
                return EncryptChunkChaCha20(plaintext, fileKey, chunkIndex, fileSalt, isFirstChunk);

            default:
                throw new ArgumentException($"サポートされていないチャンク暗号化アルゴリズム: {algorithm}");
        }
    }

    /// <summary>AES-256-GCM でチャンクを暗号化。</summary>
    private static byte[] EncryptChunkAesGcm(byte[] plaintext, byte[] fileKey, int chunkIndex, byte[] fileSalt, bool isFirstChunk)
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

    /// <summary>ChaCha20-Poly1305 でチャンクを暗号化。</summary>
    private static byte[] EncryptChunkChaCha20(byte[] plaintext, byte[] fileKey, int chunkIndex, byte[] fileSalt, bool isFirstChunk)
    {
        byte[] nonce = DeriveChunkNonce(fileKey, chunkIndex);
        byte[] aad = BitConverter.GetBytes(chunkIndex);

        // ChaCha20 で平文を暗号化し、(key, nonce) ペアから Poly1305 ワンタイム鍵 (r, s) を導出する。
        // Poly1305 のワンタイム鍵は counter=0 の ChaCha20 ブロックから導出されるため、
        // (key, nonce) は暗号鍵と nonce 導出で 1 回ずつ別 ChaCha20 呼び出しで使われるだけで
        // 同じ (r, s) を 2 回再導出するわけではない。
        // 注: ChaCha20Poly1305.Encrypt 内部の Poly1305 鍵導出は counter=0 で行われ、
        // 暗号化は counter=1 で行われるため、(r, s) と暗号化キーストリームは別ブロック。
        var (encNonce, ciphertext, _) = ChaCha20Poly1305.Encrypt(plaintext, fileKey, nonce);

        // AAD を含めて Poly1305 タグを計算 (RFC 7539 §2.8:
        //   mac_data = aad || pad16(aad) || ciphertext || pad16(ciphertext) || le64(len(aad)) || le64(len(ct))
        // )
        byte[] tag = Poly1305ComputeTagWithAad(fileKey, nonce, ciphertext, aad);

        // フォーマット: [fileSalt (first chunk)] || [ciphertext] || [tag]
        int totalLen = (isFirstChunk ? SaltSize : 0) + ciphertext.Length + tag.Length;
        byte[] result = new byte[totalLen];
        int offset = 0;
        if (isFirstChunk)
        {
            Buffer.BlockCopy(fileSalt, 0, result, 0, SaltSize);
            offset = SaltSize;
        }
        Buffer.BlockCopy(ciphertext, 0, result, offset, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, offset + ciphertext.Length, tag.Length);
        return result;
    }

    /// <summary>チャンクを復号する。</summary>
    public static byte[] DecryptChunk(byte[] encData, byte[] fileKey, int chunkIndex, out byte[] fileSalt, string algorithm = "aes-256-gcm")
    {
        fileSalt = [];
        int offset = 0;

        if (chunkIndex == 0 && encData.Length > SaltSize + GcmTagSize)
        {
            fileSalt = new byte[SaltSize];
            Buffer.BlockCopy(encData, 0, fileSalt, 0, SaltSize);
            offset = SaltSize;
        }

        switch (algorithm.ToLowerInvariant())
        {
            case "aes-256-gcm":
                return DecryptChunkAesGcm(encData, fileKey, chunkIndex, offset);

            case "chacha20-poly1305":
                return DecryptChunkChaCha20(encData, fileKey, chunkIndex, offset);

            default:
                throw new ArgumentException($"サポートされていないチャンク暗号化アルゴリズム: {algorithm}");
        }
    }

    /// <summary>AES-256-GCM でチャンクを復号。</summary>
    private static byte[] DecryptChunkAesGcm(byte[] encData, byte[] fileKey, int chunkIndex, int offset)
    {
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

    /// <summary>ChaCha20-Poly1305 でチャンクを復号。</summary>
    private static byte[] DecryptChunkChaCha20(byte[] encData, byte[] fileKey, int chunkIndex, int offset)
    {
        int ctLen = encData.Length - offset - GcmTagSize;
        byte[] ct = new byte[ctLen];
        byte[] tag = new byte[GcmTagSize];
        Buffer.BlockCopy(encData, offset, ct, 0, ctLen);
        Buffer.BlockCopy(encData, offset + ctLen, tag, 0, GcmTagSize);

        byte[] nonce = DeriveChunkNonce(fileKey, chunkIndex);
        byte[] aad = BitConverter.GetBytes(chunkIndex);

        // Poly1305 タグ検証（AAD 付き、RFC 7539 §2.8 形式の mac_data）
        if (!Poly1305VerifyTagWithAad(fileKey, nonce, ct, tag, aad))
            throw new CryptographicException("ChaCha20-Poly1305 タグ検証失敗。");

        // タグ検証 OK → ChaCha20 で復号。
        // 注: ここではタグ検証は自前で行っているため、Decrypt 側の再検証は冗長だが
        // ChaCha20Poly1305.Decrypt は暗号文復号専用 API なので、内部で再検証しない
        // （検証スキップで復号だけ行う）ラッパーを用意する。
        byte[] plaintext = new byte[ctLen];
        ChaCha20Poly1305.ChaCha20Decrypt(fileKey, nonce, counter: 1, ct, plaintext);
        return plaintext;
    }

    // ---- ファイル名暗号化 ----

    public static string EncryptFilename(string plainName, byte[] masterKey, string algorithm = "aes-256-gcm")
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(GcmNonceSize);
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainName);

        byte[] ct, tag;

        switch (algorithm.ToLowerInvariant())
        {
            case "aes-256-gcm":
                ct = new byte[plainBytes.Length];
                tag = new byte[GcmTagSize];
                using (var gcm = new AesGcm(masterKey, GcmTagSize))
                {
                    gcm.Encrypt(nonce, plainBytes, ct, tag);
                }
                break;

            case "chacha20-poly1305":
                var (n, c, t) = ChaCha20Poly1305.Encrypt(plainBytes, masterKey, nonce);
                ct = c;
                tag = t;
                break;

            default:
                throw new ArgumentException($"サポートされていないファイル名暗号化アルゴリズム: {algorithm}");
        }

        byte[] result = new byte[GcmNonceSize + ct.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, GcmNonceSize);
        Buffer.BlockCopy(ct, 0, result, GcmNonceSize, ct.Length);
        Buffer.BlockCopy(tag, 0, result, GcmNonceSize + ct.Length, tag.Length);
        return Convert.ToBase64String(result);
    }

    public static string DecryptFilename(string encBase64, byte[] masterKey, string algorithm = "aes-256-gcm")
    {
        byte[] raw = Convert.FromBase64String(encBase64);
        byte[] nonce = raw[..GcmNonceSize];
        byte[] ct = raw[GcmNonceSize..^GcmTagSize];
        byte[] tag = raw[^GcmTagSize..];

        byte[] plain;

        switch (algorithm.ToLowerInvariant())
        {
            case "aes-256-gcm":
                plain = new byte[ct.Length];
                using (var gcm = new AesGcm(masterKey, GcmTagSize))
                {
                    gcm.Decrypt(nonce, ct, tag, plain);
                }
                break;

            case "chacha20-poly1305":
                plain = ChaCha20Poly1305.Decrypt(ct, tag, nonce, masterKey);
                break;

            default:
                throw new ArgumentException($"サポートされていないファイル名暗号化アルゴリズム: {algorithm}");
        }

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

    /// <summary>
    /// Poly1305 タグ生成（AAD 付き、RFC 7539 §2.8 準拠）。
    /// mac_data = aad || pad16(aad) || ciphertext || pad16(ciphertext) || le64(len(aad)) || le64(len(ct))
    /// Poly1305 ワンタイム鍵 (r, s) は (key, nonce) ペアから 1 回だけ導出する。
    /// </summary>
    private static byte[] Poly1305ComputeTagWithAad(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad)
    {
        byte[] macData = BuildPoly1305MacData(aad, ciphertext);
        return ChaCha20Poly1305.ComputePoly1305Tag(key, nonce, macData);
    }

    /// <summary>
    /// Poly1305 タグ検証（AAD 付き、RFC 7539 §2.8 準拠、定数時間比較）。
    /// </summary>
    private static bool Poly1305VerifyTagWithAad(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag, byte[] aad)
    {
        byte[] macData = BuildPoly1305MacData(aad, ciphertext);
        return ChaCha20Poly1305.VerifyPoly1305Tag(key, nonce, macData, tag);
    }

    /// <summary>
    /// RFC 7539 §2.8 形式の Poly1305 入力データを構築。
    /// </summary>
    private static byte[] BuildPoly1305MacData(byte[] aad, byte[] ciphertext)
    {
        // pad16(x) = 16 バイト境界までのゼロパディング
        int aadPad = (16 - (aad.Length % 16)) % 16;
        int ctPad = (16 - (ciphertext.Length % 16)) % 16;
        int totalLen = aad.Length + aadPad + ciphertext.Length + ctPad + 16; // +16 for two le64 lengths

        byte[] data = new byte[totalLen];
        int pos = 0;
        Buffer.BlockCopy(aad, 0, data, pos, aad.Length);
        pos += aad.Length + aadPad;  // aadPad 分のゼロは初期化済み
        Buffer.BlockCopy(ciphertext, 0, data, pos, ciphertext.Length);
        pos += ciphertext.Length + ctPad;
        // le64(aad.Length)
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(pos, 8), aad.Length);
        pos += 8;
        // le64(ciphertext.Length)
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(pos, 8), ciphertext.Length);
        return data;
    }
}
