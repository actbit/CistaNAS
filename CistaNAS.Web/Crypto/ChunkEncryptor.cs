using System.Security.Cryptography;

namespace CistaNAS.Web.Crypto;

/// <summary>
/// チャンク単位の AES-XTS 暗号化ヘルパー。
/// ボリューム全体で一意なセクタインデックスを保証するため、
/// nonce = chunkIndex * sectorsPerChunk で算出。
/// </summary>
public static class ChunkEncryptor
{
    /// <summary>
    /// 平文チャンクを AES-XTS で暗号化する。
    /// </summary>
    /// <param name="masterKey">マスターキー（K1||K2, 64 バイト）。</param>
    /// <param name="chunkIndex">チャンクインデックス（0 起算）。</param>
    /// <param name="sectorSize">セクタサイズ（ボリュームの SectorSize）。</param>
    /// <param name="chunkSize">チャンクサイズ（バイト）。</param>
    /// <param name="plaintext">平文データ。</param>
    /// <returns>暗号化済みデータ（16 の倍数にパディング済み）。</returns>
    public static byte[] EncryptChunk(ReadOnlySpan<byte> masterKey, int chunkIndex, int sectorSize, int chunkSize, ReadOnlySpan<byte> plaintext)
    {
        // セクタサイズが未設定（E2EE 等）の場合はブロックサイズ（16）を使用
        if (sectorSize <= 0) sectorSize = 16;

        // データを 16 の倍数にパディング
        int paddedLength = PadToBlockSize(plaintext.Length);
        byte[] padded = new byte[paddedLength];
        plaintext.CopyTo(padded);

        long firstSector = (long)chunkIndex * (chunkSize / sectorSize);

        using var transform = new AesXtsTransform(masterKey, sectorSize);
        transform.Encrypt(firstSector, padded, padded);
        return padded;
    }

    /// <summary>
    /// 暗号化チャンクを AES-XTS で復号する。
    /// </summary>
    /// <param name="masterKey">マスターキー（K1||K2, 64 バイト）。</param>
    /// <param name="chunkIndex">チャンクインデックス（0 起算）。</param>
    /// <param name="sectorSize">セクタサイズ（ボリュームの SectorSize）。</param>
    /// <param name="chunkSize">チャンクサイズ（バイト）。</param>
    /// <param name="ciphertext">暗号化データ。</param>
    /// <param name="originalLength">復号後の元データ長。</param>
    /// <returns>復号済みデータ（元の長さにトリム済み）。</returns>
    public static byte[] DecryptChunk(ReadOnlySpan<byte> masterKey, int chunkIndex, int sectorSize, int chunkSize, ReadOnlySpan<byte> ciphertext, int originalLength)
    {
        // セクタサイズが未設定（E2EE 等）の場合はブロックサイズ（16）を使用
        if (sectorSize <= 0) sectorSize = 16;

        byte[] padded = ciphertext.ToArray();

        long firstSector = (long)chunkIndex * (chunkSize / sectorSize);

        using var transform = new AesXtsTransform(masterKey, sectorSize);
        transform.Decrypt(firstSector, padded, padded);

        // 元の長さにトリム
        if (originalLength < padded.Length)
            Array.Resize(ref padded, originalLength);
        return padded;
    }

    /// <summary>チャンクのセクタインデックスを取得する。</summary>
    public static long GetFirstSectorIndex(int chunkIndex, int chunkSize, int sectorSize)
        => (long)chunkIndex * (chunkSize / sectorSize);

    /// <summary>データ長を 16 の倍数に切り上げる。</summary>
    internal static int PadToBlockSize(int length)
    {
        const int block = 16;
        return (length + block - 1) / block * block;
    }
}
