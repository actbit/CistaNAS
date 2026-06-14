using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace CistaNAS.Shared.Crypto;

/// <summary>
/// E2EE チャンク暗号化。AES-256-GCM および ChaCha20-Poly1305 をサポート。
/// </summary>
public static class E2eeCrypto
{
    /// <summary>AES-GCM ノンスサイズ（バイト）。</summary>
    public const int GcmNonceSize = 12;

    /// <summary>認証タグサイズ（バイト）。</summary>
    public const int GcmTagSize = 16;

    /// <summary>ファイル Salt サイズ（バイト）。</summary>
    public const int SaltSize = 16;

    /// <summary>マスターキーサイズ（バイト）。</summary>
    public const int MasterKeySize = 32;

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
        byte[] nonce = DeriveChunkNonce(fileKey, fileSalt, chunkIndex);
        byte[] aad = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(aad, chunkIndex);
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
        byte[] nonce = DeriveChunkNonce(fileKey, fileSalt, chunkIndex);
        byte[] aad = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(aad, chunkIndex);

        // ChaCha20 で暗号化（counter=1）。Poly1305 タグ計算は行わない。
        // その後、AAD 付きで Poly1305 タグを 1 回だけ計算する。
        // これにより、同じ (key, nonce) から Poly1305 ワンタイム鍵 (r, s) を
        // 1 回だけ導出する（RFC 7539 準拠）。
        byte[] ciphertext = new byte[plaintext.Length];
        ChaCha20Poly1305.ChaCha20Encrypt(fileKey, nonce, 1, ciphertext, plaintext);

        // AAD を含めて Poly1305 タグを計算 (RFC 7539 §2.8)
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

    /// <summary>チャンクを復号する（fileSaltを指定）。</summary>
    public static byte[] DecryptChunk(byte[] encData, byte[] fileKey, int chunkIndex, byte[] fileSalt, string algorithm = "aes-256-gcm")
    {
        int offset = chunkIndex == 0 && fileSalt.Length > 0 ? SaltSize : 0;

        switch (algorithm.ToLowerInvariant())
        {
            case "aes-256-gcm":
                return DecryptChunkAesGcm(encData, fileKey, chunkIndex, fileSalt, offset);

            case "chacha20-poly1305":
                return DecryptChunkChaCha20(encData, fileKey, chunkIndex, fileSalt, offset);

            default:
                throw new ArgumentException($"サポートされていないチャンク暗号化アルゴリズム: {algorithm}");
        }
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
                return DecryptChunkAesGcm(encData, fileKey, chunkIndex, fileSalt, offset);

            case "chacha20-poly1305":
                return DecryptChunkChaCha20(encData, fileKey, chunkIndex, fileSalt, offset);

            default:
                throw new ArgumentException($"サポートされていないチャンク暗号化アルゴリズム: {algorithm}");
        }
    }

    /// <summary>AES-256-GCM でチャンクを復号。</summary>
    private static byte[] DecryptChunkAesGcm(byte[] encData, byte[] fileKey, int chunkIndex, byte[] fileSalt, int offset)
    {
        if (encData.Length < offset + GcmTagSize)
            throw new CryptographicException("暗号化データが短すぎます。");
        int ctLen = encData.Length - offset - GcmTagSize;
        byte[] ct = new byte[ctLen];
        byte[] tag = new byte[GcmTagSize];
        Buffer.BlockCopy(encData, offset, ct, 0, ctLen);
        Buffer.BlockCopy(encData, offset + ctLen, tag, 0, GcmTagSize);

        byte[] nonce = DeriveChunkNonce(fileKey, fileSalt, chunkIndex);
        byte[] aad = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(aad, chunkIndex);
        byte[] plain = new byte[ctLen];
        using var gcm = new AesGcm(fileKey, GcmTagSize);
        gcm.Decrypt(nonce, ct, tag, plain, aad);
        return plain;
    }

    /// <summary>ChaCha20-Poly1305 でチャンクを復号。</summary>
    private static byte[] DecryptChunkChaCha20(byte[] encData, byte[] fileKey, int chunkIndex, byte[] fileSalt, int offset)
    {
        if (encData.Length < offset + GcmTagSize)
            throw new CryptographicException("暗号化データが短すぎます。");
        int ctLen = encData.Length - offset - GcmTagSize;
        byte[] ct = new byte[ctLen];
        byte[] tag = new byte[GcmTagSize];
        Buffer.BlockCopy(encData, offset, ct, 0, ctLen);
        Buffer.BlockCopy(encData, offset + ctLen, tag, 0, GcmTagSize);

        byte[] nonce = DeriveChunkNonce(fileKey, fileSalt, chunkIndex);
        byte[] aad = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(aad, chunkIndex);

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

    // ---- ECDH 鍵交換 (P-256) ----

    /// <summary>ECIES の HKDF info 文字列。WASM/Web の e2ee.js と統一。</summary>
    private const string EciesInfo = "CistaNAS-ECIES";

    /// <summary>ECDH P-256 鍵ペアを生成し、(publicKey, privateKey) を返す。
    /// 公開鍵は raw 非圧縮点（0x04 || X[32] || Y[32], 65 バイト）。ブラウザ exportKey("raw") と一致。
    /// 秘密鍵は SEC1（ExportECPrivateKey）。ローカル完結でサーバーへは送らない。</summary>
    public static (byte[] PublicKey, byte[] PrivateKey) GenerateEcdhKeyPair()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var pubKey = ExportRawPublicKey(ecdh.ExportParameters(false).Q);
        var privKey = ecdh.ExportECPrivateKey();
        return (pubKey, privKey);
    }

    /// <summary>ECIES ラップ: 相手の公開鍵でマスターキーを共有鍵暗号化する。
    /// WASM/Web の e2ee.js ecdhWrap とプロトコル互換
    /// （raw 公開鍵 + HKDF-SHA256(salt=空, info="CistaNAS-ECIES") + AES-256-GCM）。</summary>
    public static (byte[] EphemeralPublicKey, byte[] Nonce, byte[] Ciphertext, byte[] Tag) EcdhWrap(
        byte[] masterKey, byte[] recipientPublicKeyRaw)
    {
        // 一時鍵ペア生成
        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        // 相手の公開鍵を raw からインポート
        using var recipient = ImportPublicKeyFromRaw(recipientPublicKeyRaw);

        // 生の ECDH 共有秘密 Z（ブラウザ crypto.subtle.deriveBits("ECDH", 256) とバイト完全一致）
        byte[] sharedSecret = ephemeral.DeriveRawSecretAgreement(recipient.PublicKey);

        // HKDF-SHA256 でラップ鍵を導出（salt=空）
        byte[] wrappingKey = HkdfSha256(sharedSecret, Array.Empty<byte>(),
            Encoding.UTF8.GetBytes(EciesInfo), 32);
        CryptographicOperations.ZeroMemory(sharedSecret);

        // AES-256-GCM でマスターキーを暗号化
        var (nonce, ct, tag) = WrapMasterKey(masterKey, wrappingKey, "aes-256-gcm");
        CryptographicOperations.ZeroMemory(wrappingKey);

        // 一時公開鍵を raw でエクスポート
        byte[] ephemeralPubKey = ExportRawPublicKey(ephemeral.ExportParameters(false).Q);
        return (ephemeralPubKey, nonce, ct, tag);
    }

    /// <summary>ECIES アンラップ: 自分の秘密鍵でマスターキーを復号する。
    /// WASM/Web の e2ee.js ecdhUnwrap とプロトコル互換。</summary>
    public static byte[] EcdhUnwrap(byte[] nonce, byte[] ct, byte[] tag,
        byte[] ephemeralPublicKeyRaw, byte[] myPrivateKeySec1)
    {
        // 自分の秘密鍵を SEC1 からインポート
        using var mine = ECDiffieHellman.Create();
        mine.ImportECPrivateKey(myPrivateKeySec1, out _);

        // 相手の一時公開鍵を raw からインポート
        using var ephemeral = ImportPublicKeyFromRaw(ephemeralPublicKeyRaw);

        // 生の ECDH 共有秘密 Z
        byte[] sharedSecret = mine.DeriveRawSecretAgreement(ephemeral.PublicKey);

        // HKDF-SHA256 でラップ鍵を導出
        byte[] wrappingKey = HkdfSha256(sharedSecret, Array.Empty<byte>(),
            Encoding.UTF8.GetBytes(EciesInfo), 32);
        CryptographicOperations.ZeroMemory(sharedSecret);

        try
        {
            return UnwrapMasterKey(nonce, ct, tag, wrappingKey, "aes-256-gcm");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
        }
    }

    /// <summary>raw 非圧縮点公開鍵（0x04 || X[32] || Y[32], 65 バイト）を ECPoint から構築。</summary>
    private static byte[] ExportRawPublicKey(ECPoint q)
    {
        byte[] raw = new byte[65];
        raw[0] = 0x04;
        Buffer.BlockCopy(PadField(q.X), 0, raw, 1, 32);
        Buffer.BlockCopy(PadField(q.Y), 0, raw, 33, 32);
        return raw;
    }

    /// <summary>raw 非圧縮点公開鍵（65 バイト）から ECDiffieHellman を構築。</summary>
    private static ECDiffieHellman ImportPublicKeyFromRaw(byte[] raw)
    {
        if (raw is null || raw.Length != 65 || raw[0] != 0x04)
            throw new ArgumentException("公開鍵は raw 非圧縮点 65 バイト（0x04 || X || Y）である必要があります。", nameof(raw));

        var ecp = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = raw[1..33], Y = raw[33..65] }
        };
        return ECDiffieHellman.Create(ecp);
    }

    /// <summary>P-256 フィールド要素を 32 バイトに左ゼロパディング（leading zero の strip 対策）。</summary>
    private static byte[] PadField(byte[]? value)
    {
        if (value is null) return new byte[32];
        if (value.Length == 32) return value;
        if (value.Length > 32) throw new ArgumentException("フィールド要素が 32 バイトを超えています。");
        byte[] padded = new byte[32];
        Buffer.BlockCopy(value, 0, padded, 32 - value.Length, value.Length);
        return padded;
    }

    // ---- 内部ヘルパー ----

    /// <summary>
    /// チャンクノンスを導出する。
    /// fileKey || fileSalt || chunkIndex で HMAC-SHA256 を計算し、先頭12バイトをノンスとして使用。
    /// fileSalt を含めることで、FileKey 漏洩時の Nonce 予測可能性を低減し、
    /// ファイルごとに一意な Nonce 空間を保証する。
    /// </summary>
    private static byte[] DeriveChunkNonce(byte[] fileKey, byte[] fileSalt, int chunkIndex)
    {
        using var hmac = new HMACSHA256(fileKey);
        // fileSalt || chunkIndex で HMAC（fileKey は鍵として HMACSHA256 に渡済み）
        hmac.TransformBlock(fileSalt, 0, fileSalt.Length, null, 0);

        byte[] indexBytes = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(indexBytes, chunkIndex);
        hmac.TransformBlock(indexBytes, 0, indexBytes.Length, null, 0);
        hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

        return hmac.Hash[..GcmNonceSize];
    }

    private static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int outputLength)
    {
        const int HashLength = 32; // SHA-256
        if (outputLength > 255 * HashLength)
            throw new ArgumentOutOfRangeException(nameof(outputLength),
                $"HKDF 出力長は {255 * HashLength} バイト以下である必要があります。");

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
