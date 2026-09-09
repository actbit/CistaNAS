using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace CistaNAS.Shared.Crypto;

/// <summary>チャンク暗号化の v2 コンテキスト。AAD / nonce 導出に全項目が bind される。</summary>
public readonly record struct E2eeChunkContext(
    string VolumeId,
    string FileId,
    int ChunkIndex,
    int Revision,
    int KeyEpoch);

/// <summary>
/// 共有 E2EE crypto format v2。
///
/// - GroupKey epoch: メンバー集合が縮小（revoke）するたびに新しい GroupKey を生成し、
///   remaining members の公開鍵に対して ECDH + HKDF + AES-256-GCM（AAD 付き）で個別ラップする。
/// - per-file random DEK: ファイルごとに CSPRNG の 32 バイト DEK を生成し、チャンクは DEK で暗号化。
///   GroupKey ローテーション時は DEK の再ラップのみで済み、ファイル本体の再暗号化は不要。
/// - 強化 AAD: volumeId / fileId / chunkIndex / revision / keyEpoch を AEAD の認証対象に含め、
///   別ファイル・別 epoch 間での正規暗号文の差し替えを防ぐ。
///
/// チャンクのワイヤ形式は v1 と同型（[fileSalt (先頭チャンクのみ)] || ciphertext || tag）。
/// CryptoFormatVersion はカタログ側のファイル KeyEpoch（0 = v1、≥1 = v2）で判別する。
/// </summary>
public static class E2eeV2
{
    /// <summary>GroupKey サイズ（バイト）。</summary>
    public const int GroupKeySize = 32;

    /// <summary>per-file DEK サイズ（バイト）。</summary>
    public const int FileKeySize = 32;

    /// <summary>v2 形式の識別子（カタログ / プロトコル表記用）。</summary>
    public const int CryptoFormatVersion = 2;

    // AAD ドメイン分離プレフィックス（用途ごとに異なる定数 → クロスプロトコル転用を防止）
    private static ReadOnlySpan<byte> ChunkAadPrefix => "CISTAV2\x01"u8;
    private static ReadOnlySpan<byte> FileKeyAadPrefix => "CISTAV2\x02"u8;
    private static ReadOnlySpan<byte> GroupKeyAadPrefix => "CISTAV2\x03"u8;

    private const int NonceSize = E2eeCrypto.GcmNonceSize;
    private const int TagSize = E2eeCrypto.GcmTagSize;
    private const int SaltSize = E2eeCrypto.SaltSize;

    /// <summary>GroupKey を生成する（CSPRNG 32 バイト）。</summary>
    public static byte[] GenerateGroupKey() => RandomNumberGenerator.GetBytes(GroupKeySize);

    /// <summary>per-file DEK を生成する（CSPRNG 32 バイト）。</summary>
    public static byte[] GenerateFileKey() => RandomNumberGenerator.GetBytes(FileKeySize);

    /// <summary>per-file salt を生成する（nonce 空間の分離用。ワイヤ形式では先頭チャンクに平文で付加）。</summary>
    public static byte[] GenerateFileSalt() => RandomNumberGenerator.GetBytes(SaltSize);

    /// <summary>
    /// 公開鍵（raw 非圧縮点 65 バイト）の fingerprint（SHA-256、大文字 hex）。
    /// TOFU public-key pinning で使用する。
    /// </summary>
    public static string ComputeFingerprint(ReadOnlySpan<byte> publicKeyRaw)
        => Convert.ToHexString(SHA256.HashData(publicKeyRaw));

    /// <summary>GroupKey epoch の AAD（ECDH ラップ用）を構築する。</summary>
    internal static byte[] BuildGroupKeyAad(string volumeId, int keyEpoch, string username)
    {
        var prefix = GroupKeyAadPrefix.ToArray();
        var volumeIdBytes = Encoding.UTF8.GetBytes(volumeId);
        var usernameBytes = Encoding.UTF8.GetBytes(username);
        byte[] aad = new byte[prefix.Length + 4 + volumeIdBytes.Length + 4 + 4 + usernameBytes.Length];
        int offset = 0;
        prefix.CopyTo(aad, offset); offset += prefix.Length;
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(offset), volumeIdBytes.Length); offset += 4;
        volumeIdBytes.CopyTo(aad, offset); offset += volumeIdBytes.Length;
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(offset), keyEpoch); offset += 4;
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(offset), usernameBytes.Length); offset += 4;
        usernameBytes.CopyTo(aad, offset);
        return aad;
    }

    /// <summary>per-file DEK ラップの AAD を構築する。</summary>
    internal static byte[] BuildFileKeyAad(string volumeId, string fileId, int keyEpoch)
    {
        var prefix = FileKeyAadPrefix.ToArray();
        var volumeIdBytes = Encoding.UTF8.GetBytes(volumeId);
        var fileIdBytes = Encoding.UTF8.GetBytes(fileId);
        byte[] aad = new byte[prefix.Length + 4 + volumeIdBytes.Length + 4 + fileIdBytes.Length + 4];
        int offset = 0;
        prefix.CopyTo(aad, offset); offset += prefix.Length;
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(offset), volumeIdBytes.Length); offset += 4;
        volumeIdBytes.CopyTo(aad, offset); offset += volumeIdBytes.Length;
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(offset), fileIdBytes.Length); offset += 4;
        fileIdBytes.CopyTo(aad, offset); offset += fileIdBytes.Length;
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(offset), keyEpoch);
        return aad;
    }

    /// <summary>チャンク AEAD の AAD を構築する。</summary>
    internal static byte[] BuildChunkAad(in E2eeChunkContext ctx)
    {
        var prefix = ChunkAadPrefix.ToArray();
        var volumeIdBytes = Encoding.UTF8.GetBytes(ctx.VolumeId);
        var fileIdBytes = Encoding.UTF8.GetBytes(ctx.FileId);
        byte[] aad = new byte[prefix.Length + 4 + volumeIdBytes.Length + 4 + fileIdBytes.Length + 12];
        int offset = 0;
        prefix.CopyTo(aad, offset); offset += prefix.Length;
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(offset), volumeIdBytes.Length); offset += 4;
        volumeIdBytes.CopyTo(aad, offset); offset += volumeIdBytes.Length;
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(offset), fileIdBytes.Length); offset += 4;
        fileIdBytes.CopyTo(aad, offset); offset += fileIdBytes.Length;
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(offset), ctx.ChunkIndex); offset += 4;
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(offset), ctx.Revision); offset += 4;
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(offset), ctx.KeyEpoch);
        return aad;
    }

    // ---- GroupKey の ECDH ラップ（AAD 付き ECIES） ----

    /// <summary>
    /// GroupKey を受信者の公開鍵に対して ECDH + HKDF + AES-256-GCM でラップする。
    /// AAD に volumeId / keyEpoch / username を bind（wrapped key の転用・差し替えを防止）。
    /// e2ee.js の ecdhWrapGroupKey とプロトコル互換（HKDF info は "CistaNAS-ECIES-V2"）。
    /// </summary>
    public static (byte[] EphemeralPublicKey, byte[] Nonce, byte[] Ciphertext, byte[] Tag) EcdhWrapGroupKey(
        byte[] groupKey, byte[] recipientPublicKeyRaw, string volumeId, int keyEpoch, string username)
    {
        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var recipient = E2eeCrypto.ImportPublicKeyFromRaw(recipientPublicKeyRaw);
        byte[] sharedSecret = ephemeral.DeriveRawSecretAgreement(recipient.PublicKey);

        byte[] wrappingKey = E2eeCrypto.HkdfSha256(sharedSecret, Array.Empty<byte>(),
            Encoding.UTF8.GetBytes("CistaNAS-ECIES-V2"), 32);
        CryptographicOperations.ZeroMemory(sharedSecret);
        try
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
            byte[] ct = new byte[groupKey.Length];
            byte[] tag = new byte[TagSize];
            byte[] aad = BuildGroupKeyAad(volumeId, keyEpoch, username);
            using (var gcm = new AesGcm(wrappingKey, TagSize))
                gcm.Encrypt(nonce, groupKey, ct, tag, aad);
            CryptographicOperations.ZeroMemory(wrappingKey);

            byte[] ephPub = E2eeCrypto.ExportRawPublicKey(ephemeral.ExportParameters(false).Q);
            return (ephPub, nonce, ct, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
        }
    }

    /// <summary>
    /// 自分宛てにラップされた GroupKey を秘密鍵（SEC1）でアンラップする。
    /// AAD（volumeId / keyEpoch / username）が一致しない場合は CryptographicException。
    /// </summary>
    public static byte[] EcdhUnwrapGroupKey(
        byte[] nonce, byte[] ciphertext, byte[] tag, byte[] ephemeralPublicKeyRaw,
        byte[] myPrivateKeySec1, string volumeId, int keyEpoch, string username)
    {
        using var mine = ECDiffieHellman.Create();
        mine.ImportECPrivateKey(myPrivateKeySec1, out _);
        using var ephemeral = E2eeCrypto.ImportPublicKeyFromRaw(ephemeralPublicKeyRaw);
        byte[] sharedSecret = mine.DeriveRawSecretAgreement(ephemeral.PublicKey);

        byte[] wrappingKey = E2eeCrypto.HkdfSha256(sharedSecret, Array.Empty<byte>(),
            Encoding.UTF8.GetBytes("CistaNAS-ECIES-V2"), 32);
        CryptographicOperations.ZeroMemory(sharedSecret);
        try
        {
            byte[] groupKey = new byte[ciphertext.Length];
            byte[] aad = BuildGroupKeyAad(volumeId, keyEpoch, username);
            using (var gcm = new AesGcm(wrappingKey, TagSize))
                gcm.Decrypt(nonce, ciphertext, tag, groupKey, aad);
            return groupKey;
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new CryptographicException("GroupKey のアンラップに失敗しました（AAD または鍵が一致しません）。");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
        }
    }

    // ---- per-file DEK ラップ ----

    /// <summary>
    /// per-file DEK を GroupKey で AES-256-GCM ラップする。
    /// AAD に volumeId / fileId / keyEpoch を bind（カタログ上の WrappedFileKey の差し替え攻撃を防止）。
    /// </summary>
    public static (byte[] Nonce, byte[] Ciphertext, byte[] Tag) WrapFileKey(
        byte[] fileKey, byte[] groupKey, string volumeId, string fileId, int keyEpoch)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] ct = new byte[fileKey.Length];
        byte[] tag = new byte[TagSize];
        byte[] aad = BuildFileKeyAad(volumeId, fileId, keyEpoch);
        using var gcm = new AesGcm(groupKey, TagSize);
        gcm.Encrypt(nonce, fileKey, ct, tag, aad);
        return (nonce, ct, tag);
    }

    /// <summary>WrappedFileKey をアンラップする。AAD が一致しない（別ファイル/別 epoch への差し替え）場合は失敗。</summary>
    public static byte[] UnwrapFileKey(
        byte[] nonce, byte[] ciphertext, byte[] tag, byte[] groupKey, string volumeId, string fileId, int keyEpoch)
    {
        byte[] fileKey = new byte[ciphertext.Length];
        byte[] aad = BuildFileKeyAad(volumeId, fileId, keyEpoch);
        using var gcm = new AesGcm(groupKey, TagSize);
        gcm.Decrypt(nonce, ciphertext, tag, fileKey, aad);
        return fileKey;
    }

    // ---- チャンク暗号化（v2） ----

    /// <summary>
    /// v2 チャンクを暗号化する。鍵は per-file DEK、AAD には volumeId / fileId / chunkIndex /
    /// revision / keyEpoch を bind。ワイヤ形式は v1 同型（先頭チャンクに fileSalt を付加）。
    /// </summary>
    public static byte[] EncryptChunk(
        byte[] plaintext, byte[] fileKey, in E2eeChunkContext ctx, bool isFirstChunk, byte[] fileSalt)
    {
        byte[] nonce = DeriveChunkNonce(fileKey, fileSalt, ctx);
        byte[] aad = BuildChunkAad(ctx);
        byte[] ct = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];
        using (var gcm = new AesGcm(fileKey, TagSize))
            gcm.Encrypt(nonce, plaintext, ct, tag, aad);
        CryptographicOperations.ZeroMemory(nonce);

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

    /// <summary>v2 チャンクを復号する（fileSalt はカタログ/チャンク 0 から取得したもの）。</summary>
    public static byte[] DecryptChunk(
        byte[] encData, byte[] fileKey, in E2eeChunkContext ctx, byte[] fileSalt)
    {
        int offset = ctx.ChunkIndex == 0 && encData.Length > SaltSize + TagSize ? SaltSize : 0;
        if (encData.Length < offset + TagSize)
            throw new CryptographicException("暗号化データが短すぎます。");
        int ctLen = encData.Length - offset - TagSize;
        byte[] ct = new byte[ctLen];
        byte[] tag = new byte[TagSize];
        Buffer.BlockCopy(encData, offset, ct, 0, ctLen);
        Buffer.BlockCopy(encData, offset + ctLen, tag, 0, TagSize);

        byte[] nonce = DeriveChunkNonce(fileKey, fileSalt, ctx);
        byte[] aad = BuildChunkAad(ctx);
        byte[] plain = new byte[ctLen];
        try
        {
            using var gcm = new AesGcm(fileKey, TagSize);
            gcm.Decrypt(nonce, ct, tag, plain, aad);
            return plain;
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new CryptographicException(
                $"チャンク {ctx.ChunkIndex} の復号に失敗しました（改ざん、または volumeId/fileId/revision/keyEpoch が暗号化時と一致しません）。");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    /// <summary>
    /// v2 チャンクノンス導出: HMAC-SHA256(dek, fileSalt || le32(chunkIndex) || le32(revision) || le32(keyEpoch))。
    /// v1 と異なり keyEpoch を常に入力に含める（v2 は epoch ≥ 1 で固定のため後方互換問題なし）。
    /// </summary>
    private static byte[] DeriveChunkNonce(byte[] fileKey, byte[] fileSalt, in E2eeChunkContext ctx)
    {
        using var hmac = new HMACSHA256(fileKey);
        hmac.TransformBlock(fileSalt, 0, fileSalt.Length, null, 0);
        byte[] indexBytes = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(indexBytes, ctx.ChunkIndex);
        hmac.TransformBlock(indexBytes, 0, indexBytes.Length, null, 0);
        byte[] revBytes = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(revBytes, ctx.Revision);
        hmac.TransformBlock(revBytes, 0, revBytes.Length, null, 0);
        byte[] epochBytes = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(epochBytes, ctx.KeyEpoch);
        hmac.TransformBlock(epochBytes, 0, epochBytes.Length, null, 0);
        hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return hmac.Hash![..NonceSize];
    }
}
