using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CistaNAS.Web.Crypto;

/// <summary>
/// チャンク単位の暗号化ヘルパー。
/// ボリューム全体で一意なセクタインデックスを保証するため、
/// nonce = chunkIndex * sectorsPerChunk で算出。
/// AES-256-XTS および ChaCha20 をサポート。
/// </summary>
public static class ChunkEncryptor
{
    /// <summary>
    /// 平文チャンクを暗号化する。
    /// </summary>
    /// <param name="masterKey">マスターキー（64 バイト for AES-XTS, 32 バイト for ChaCha20）。</param>
    /// <param name="algorithm">暗号化アルゴリズム。</param>
    /// <param name="chunkIndex">チャンクインデックス（0 起算）。</param>
    /// <param name="sectorSize">セクタサイズ（ボリュームの SectorSize）。</param>
    /// <param name="chunkSize">チャンクサイズ（バイト）。</param>
    /// <param name="plaintext">平文データ。</param>
    /// <returns>暗号化済みデータ（16 の倍数にパディング済み）。</returns>
    public static byte[] EncryptChunk(
        ReadOnlySpan<byte> masterKey,
        CipherAlgorithm algorithm,
        int chunkIndex,
        int sectorSize,
        int chunkSize,
        ReadOnlySpan<byte> plaintext)
    {
        // セクタサイズが未設定（E2EE 等）の場合はブロックサイズ（16）を使用
        if (sectorSize <= 0) sectorSize = 16;

        // データを 16 の倍数にパディング
        int paddedLength = PadToBlockSize(plaintext.Length);
        byte[] padded = new byte[paddedLength];
        plaintext.CopyTo(padded);

        long firstSector = (long)chunkIndex * (chunkSize / sectorSize);

        switch (algorithm)
        {
            case CipherAlgorithm.Aes256Xts:
                using (var transform = new AesXtsTransform(masterKey, sectorSize))
                {
                    transform.Encrypt(firstSector, padded, padded);
                }
                break;

            case CipherAlgorithm.ChaCha20:
                ChaCha20Encrypt(masterKey, firstSector, padded, sectorSize);
                break;

            default:
                throw new ArgumentException($"サポートされていない暗号化アルゴリズム: {algorithm}");
        }

        return padded;
    }

    /// <summary>
    /// 暗号化チャンクを復号する。
    /// </summary>
    /// <param name="masterKey">マスターキー（64 バイト for AES-XTS, 32 バイト for ChaCha20）。</param>
    /// <param name="algorithm">暗号化アルゴリズム。</param>
    /// <param name="chunkIndex">チャンクインデックス（0 起算）。</param>
    /// <param name="sectorSize">セクタサイズ（ボリュームの SectorSize）。</param>
    /// <param name="chunkSize">チャンクサイズ（バイト）。</param>
    /// <param name="ciphertext">暗号化データ。</param>
    /// <param name="originalLength">復号後の元データ長。</param>
    /// <returns>復号済みデータ（元の長さにトリム済み）。</returns>
    public static byte[] DecryptChunk(
        ReadOnlySpan<byte> masterKey,
        CipherAlgorithm algorithm,
        int chunkIndex,
        int sectorSize,
        int chunkSize,
        ReadOnlySpan<byte> ciphertext,
        int originalLength)
    {
        // セクタサイズが未設定（E2EE 等）の場合はブロックサイズ（16）を使用
        if (sectorSize <= 0) sectorSize = 16;

        byte[] padded = ciphertext.ToArray();

        long firstSector = (long)chunkIndex * (chunkSize / sectorSize);

        switch (algorithm)
        {
            case CipherAlgorithm.Aes256Xts:
                using (var transform = new AesXtsTransform(masterKey, sectorSize))
                {
                    transform.Decrypt(firstSector, padded, padded);
                }
                break;

            case CipherAlgorithm.ChaCha20:
                ChaCha20Decrypt(masterKey, firstSector, padded, sectorSize);
                break;

            default:
                throw new ArgumentException($"サポートされていない暗号化アルゴリズム: {algorithm}");
        }

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

    /// <summary>ChaCha20 暗号化（サーバー側実装）。</summary>
    private static void ChaCha20Encrypt(ReadOnlySpan<byte> masterKey, long firstSector, byte[] data, int sectorSize)
    {
        const int SectorSize = 16;
        const int BlockSize = 64;
        const int NonceSize = 12;

        // ノンス生成（マスターキーから派生）
        byte[] nonce = new byte[NonceSize];
        Buffer.BlockCopy(masterKey.ToArray(), 0, nonce, 0, Math.Min(NonceSize, masterKey.Length));

        int sectorCount = data.Length / SectorSize;
        for (int s = 0; s < sectorCount; s++)
        {
            long sectorIndex = firstSector + s;
            int sectorOffset = s * SectorSize;

            // ChaCha20 暗号化（セクタインデックスをカウンタとして使用）
            uint counter = (uint)(sectorIndex * (SectorSize / BlockSize));
            ChaCha20EncryptCore(masterKey.ToArray(), nonce, counter, data.AsSpan(sectorOffset, SectorSize));
        }
    }

    /// <summary>ChaCha20 復号化（サーバー側実装）。</summary>
    private static void ChaCha20Decrypt(ReadOnlySpan<byte> masterKey, long firstSector, byte[] data, int sectorSize)
    {
        // ChaCha20 は XOR 暗号なので暗号化と復号化は同じ
        ChaCha20Encrypt(masterKey, firstSector, data, sectorSize);
    }

    /// <summary>ChaCha20 暗号化コア（RFC 7539）。</summary>
    private static void ChaCha20EncryptCore(byte[] key, byte[] nonce, uint counter, Span<byte> data)
    {
        uint[] state = InitializeChaChaState(key, nonce, counter);

        int byteCount = data.Length;
        int blockIndex = 0;

        while (byteCount > 0)
        {
            // カウンタ更新
            state[12] = (uint)blockIndex + counter;

            // ブロックキーストリーム生成
            uint[] keyStream = ChaCha20Block(state);

            // XOR 処理
            int blockSize = Math.Min(64, byteCount);
            for (int i = 0; i < blockSize; i++)
            {
                int wordIndex = i / 4;
                int byteInWord = i % 4;
                uint keyByte = (keyStream[wordIndex] >> (byteInWord * 8)) & 0xFF;
                data[blockIndex * 64 + i] = (byte)(data[blockIndex * 64 + i] ^ keyByte);
            }

            byteCount -= blockSize;
            blockIndex++;
        }
    }

    /// <summary>ChaCha20 初期状態生成。</summary>
    private static uint[] InitializeChaChaState(byte[] key, byte[] nonce, uint counter)
    {
        uint[] state = new uint[16];

        // 定数 "expand 32-byte k"
        state[0] = 0x61707865;  // "expa"
        state[1] = 0x3320646e;  // "nd 3"
        state[2] = 0x79622d32;  // "2-by"
        state[3] = 0x6b206574;  // "te k"

        // キー（32 bytes = 8 words）
        for (int i = 0; i < 8; i++)
        {
            state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(i * 4));
        }

        // カウンタ（1 word）
        state[12] = counter;

        // ノンス（12 bytes = 3 words）
        state[13] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(0));
        state[14] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(4));
        state[15] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(8));

        return state;
    }

    /// <summary>ChaCha20 ブロック処理。</summary>
    private static uint[] ChaCha20Block(uint[] state)
    {
        uint[] workingState = (uint[])state.Clone();

        // 10 double-rounds = 20 rounds
        for (int i = 0; i < 20; i += 2)
        {
            // Column rounds
            QuarterRound(workingState, 0, 4, 8, 12);
            QuarterRound(workingState, 1, 5, 9, 13);
            QuarterRound(workingState, 2, 6, 10, 14);
            QuarterRound(workingState, 3, 7, 11, 15);

            // Diagonal rounds
            QuarterRound(workingState, 0, 5, 10, 15);
            QuarterRound(workingState, 1, 6, 11, 12);
            QuarterRound(workingState, 2, 7, 8, 13);
            QuarterRound(workingState, 3, 4, 9, 14);
        }

        // 状態を加算
        for (int i = 0; i < 16; i++)
        {
            workingState[i] += state[i];
        }

        return workingState;
    }

    /// <summary>QuarterRound 関数。</summary>
    private static void QuarterRound(uint[] x, int a, int b, int c, int d)
    {
        x[a] += x[d]; x[b] = RotateLeft(x[b] ^ x[a], 16);
        x[c] += x[b]; x[d] = RotateLeft(x[d] ^ x[c], 12);
        x[a] += x[d]; x[b] = RotateLeft(x[b] ^ x[a], 8);
        x[c] += x[b]; x[d] = RotateLeft(x[d] ^ x[c], 7);
    }

    /// <summary>左ローテート。</summary>
    private static uint RotateLeft(uint value, int count)
        => (value << count) | (value >> (32 - count));
}
