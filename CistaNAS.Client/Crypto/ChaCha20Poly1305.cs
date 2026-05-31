using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace CistaNAS.Client.Crypto;

/// <summary>
/// ChaCha20-Poly1305 AEAD 暗号化アルゴリズム実装。
/// RFC 7539 に準拠。
/// </summary>
public static class ChaCha20Poly1305
{
    private const int KeySize = 32;        // 256-bit
    private const int NonceSize = 12;      // 96-bit
    private const int TagSize = 16;        // 128-bit (Poly1305 MAC)
    private const int BlockSize = 64;      // ChaCha20 ブロックサイズ

    /// <summary>暗号化。</summary>
    public static (byte[] Nonce, byte[] Ciphertext, byte[] Tag) Encrypt(
        byte[] plaintext, byte[] key, byte[] nonce)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"ChaCha20 鍵長は {KeySize} バイトである必要があります。", nameof(key));
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"ChaCha20 ノンスは {NonceSize} バイトである必要があります。", nameof(nonce));
        if (plaintext is null) throw new ArgumentNullException(nameof(plaintext));

        byte[] ciphertext = new byte[plaintext.Length];

        // ChaCha20 暗号化（カウンタ=1から開始）
        ChaCha20Encrypt(key, nonce, 1, ciphertext, plaintext);

        // Poly1305 タグ生成（RFC 7539 §2.8）
        byte[] tag = Poly1305ComputeTag(key, nonce, ciphertext);

        return (nonce, ciphertext, tag);
    }

    /// <summary>復号。</summary>
    public static byte[] Decrypt(byte[] ciphertext, byte[] tag, byte[] nonce, byte[] key)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"ChaCha20 鍵長は {KeySize} バイトである必要があります。", nameof(key));
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"ChaCha20 ノンスは {NonceSize} バイトである必要があります。", nameof(nonce));
        if (ciphertext is null) throw new ArgumentNullException(nameof(ciphertext));
        if (tag is null) throw new ArgumentNullException(nameof(tag));

        // Poly1305 タグ検証
        if (!Poly1305VerifyTag(key, nonce, ciphertext, tag))
            throw new CryptographicException("ChaCha20-Poly1305 タグ検証失敗。");

        byte[] plaintext = new byte[ciphertext.Length];
        ChaCha20Decrypt(key, nonce, 1, ciphertext, plaintext);
        return plaintext;
    }

    /// <summary>ChaCha20 暗号化（RFC 7539）。</summary>
    internal static void ChaCha20Encrypt(byte[] key, byte[] nonce, uint counter,
        Span<byte> output, ReadOnlySpan<byte> input)
    {
        uint[] state = InitializeChaChaState(key, nonce, counter);

        int byteCount = input.Length;
        int blockIndex = 0;

        while (byteCount > 0)
        {
            // カウンタ更新
            state[12] = (uint)blockIndex + counter;

            // ブロックキーストリーム生成
            uint[] keyStream = ChaCha20Block(state);

            // XOR 処理
            int blockSize = Math.Min(BlockSize, byteCount);
            for (int i = 0; i < blockSize; i++)
            {
                int wordIndex = i / 4;
                int byteInWord = i % 4;
                uint keyByte = (keyStream[wordIndex] >> (byteInWord * 8)) & 0xFF;
                output[blockIndex * BlockSize + i] = (byte)(input[blockIndex * BlockSize + i] ^ keyByte);
            }

            byteCount -= blockSize;
            blockIndex++;
        }
    }

    /// <summary>ChaCha20 復号化。</summary>
    internal static void ChaCha20Decrypt(byte[] key, byte[] nonce, uint counter,
        Span<byte> input, Span<byte> output)
    {
        // ChaCha20 は XOR 暗号なので暗号化と復号化は同じ
        ChaCha20Encrypt(key, nonce, counter, output, input);
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

    /// <summary>ChaCha20 ブロック処理（RFC 7539 §2.1.1）。</summary>
    private static uint[] ChaCha20Block(uint[] state)
    {
        uint[] workingState = (uint[])state.Clone();

        // 10 double-rounds = 20 rounds
        for (int i = 0; i < 10; i++)
        {
            // Column rounds (4回)
            QuarterRound(workingState, 0, 4, 8, 12);
            QuarterRound(workingState, 1, 5, 9, 13);
            QuarterRound(workingState, 2, 6, 10, 14);
            QuarterRound(workingState, 3, 7, 11, 15);

            // Diagonal rounds (4回)
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

    /// <summary>QuarterRound 関数（RFC 7539 §2.1.1）。</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRound(uint[] x, int a, int b, int c, int d)
    {
        // a' = a + b; d' = ROTATE(d ^ a', 16);
        x[a] += x[b]; x[d] = RotateLeft(x[d] ^ x[a], 16);
        // c' = c + d'; b' = ROTATE(b ^ c', 12);
        x[c] += x[d]; x[b] = RotateLeft(x[b] ^ x[c], 12);
        // a'' = a' + b'; d'' = ROTATE(d' ^ a'', 8);
        x[a] += x[b]; x[d] = RotateLeft(x[d] ^ x[a], 8);
        // c'' = c' + d''; b'' = ROTATE(b' ^ c'', 7);
        x[c] += x[d]; x[b] = RotateLeft(x[b] ^ x[c], 7);
    }

    /// <summary>左ローテート。</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint RotateLeft(uint value, int count)
        => (value << count) | (value >> (32 - count));

    /// <summary>Poly1305 タグ生成（RFC 7539 §2.5）。</summary>
    private static byte[] Poly1305ComputeTag(byte[] key, byte[] nonce, byte[] ciphertext)
    {
        // Poly1305 1-time key: ChaCha20(カウンタ=0) の最初の 32 バイト
        byte[] polyKey = new byte[32];
        ChaCha20Encrypt(key, nonce, 0, polyKey, polyKey);

        // r と s を抽出（RFC 7539 §2.5 でクランピング）
        // r[0-3]: b[0]下位2ビットクリア + b[3]上位4ビットクリア → & 0x0FFFFFFF
        // r[4-7]: b[0]下位4ビットクリア + b[3]上位4ビットクリア → & 0x0FFFFFFC
        // r[8-11]: b[3]上位4ビットのみクリア → & 0x0FFFFFFF
        // r[12-15]: b[0]下位4ビットクリア + b[3]上位4ビットクリア → & 0x0FFFFFFC
        uint r0 = BinaryPrimitives.ReadUInt32LittleEndian(polyKey) & 0x0FFFFFFF;
        uint r1 = BinaryPrimitives.ReadUInt32LittleEndian(polyKey[4..]) & 0x0FFFFFFC;
        uint r2 = BinaryPrimitives.ReadUInt32LittleEndian(polyKey[8..]) & 0x0FFFFFFF;
        uint r3 = BinaryPrimitives.ReadUInt32LittleEndian(polyKey[12..]) & 0x0FFFFFFC;
        uint r4 = 0;

        // s（最終的な加算）
        uint s0 = BinaryPrimitives.ReadUInt32LittleEndian(polyKey[16..]);
        uint s1 = BinaryPrimitives.ReadUInt32LittleEndian(polyKey[20..]);
        uint s2 = BinaryPrimitives.ReadUInt32LittleEndian(polyKey[24..]);
        uint s3 = BinaryPrimitives.ReadUInt32LittleEndian(polyKey[28..]);

        // Poly1305 計算
        (uint h0, uint h1, uint h2, uint h3) = Poly1305Core(ciphertext, r0, r1, r2, r3, r4);

        // 最終加算とモジュラス
        h0 += s0; h1 += s1; h2 += s2; h3 += s3;
        (h0, h1, h2, h3) = Reduce1305(h0, h1, h2, h3);

        // タグ生成（RFC 7539 §2.5.1: (h0 | (h1 << 32), h2 | (h3 << 32))）
        byte[] tag = new byte[TagSize];
        BinaryPrimitives.WriteUInt32LittleEndian(tag.AsSpan(0), h0);
        BinaryPrimitives.WriteUInt32LittleEndian(tag.AsSpan(4), h1);
        BinaryPrimitives.WriteUInt32LittleEndian(tag.AsSpan(8), h2);
        BinaryPrimitives.WriteUInt32LittleEndian(tag.AsSpan(12), h3);

        return tag;
    }

    /// <summary>Poly1305 タグ検証（タイミング攻撃対策）。</summary>
    private static bool Poly1305VerifyTag(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        byte[] computed = Poly1305ComputeTag(key, nonce, ciphertext);

        // 定数時間比較
        int result = 0;
        for (int i = 0; i < TagSize; i++)
        {
            result |= computed[i] ^ tag[i];
        }
        return result == 0;
    }

    /// <summary>Poly1305 コアアルゴリズム（RFC 7539 §2.5.1）。</summary>
    private static (uint h0, uint h1, uint h2, uint h3) Poly1305Core(
        byte[] data, uint r0, uint r1, uint r2, uint r3, uint r4)
    {
        // 26ビット制約定数
        const uint BIT_26 = 0x03FFFFFF; // 26ビットマスク

        uint h0 = 0, h1 = 0, h2 = 0, h3 = 0;
        int offset = 0;
        int length = data.Length;

        while (length > 0)
        {
            int blockSize = Math.Min(BlockSize, length);

            // データブロック読み取り（リトルエンディアン）
            uint c0 = 1; // 最下位ビットに1
            uint c1 = 0, c2 = 0, c3 = 0;

            for (int i = 0; i < blockSize; i++)
            {
                int bytePos = i * 8;
                uint byteVal = data[offset + i];

                if (bytePos < 32) {
                    c0 |= byteVal << bytePos;
                } else if (bytePos < 64) {
                    c1 |= byteVal << (bytePos - 32);
                } else if (bytePos < 96) {
                    c2 |= byteVal << (bytePos - 64);
                } else {
                    c3 |= byteVal << (bytePos - 96);
                }
            }
            offset += blockSize;
            length -= blockSize;

            // 積和: h = (h + c) * r mod (2^130 - 5)
            // 各項を26ビットに制約
            ulong h0_c = (h0 & BIT_26) + (c0 & BIT_26);
            ulong carry = h0_c >> 26;
            h0_c &= BIT_26;

            ulong h1_c = (h1 & BIT_26) + (c1 & BIT_26) + carry;
            carry = h1_c >> 26;
            h1_c &= BIT_26;

            ulong h2_c = (h2 & BIT_26) + (c2 & BIT_26) + carry;
            carry = h2_c >> 26;
            h2_c &= BIT_26;

            ulong h3_c = (h3 & BIT_26) + (c3 & BIT_26) + carry;
            h3_c &= BIT_26;

            // 乗算: (h_c) * r
            // 各係数を26ビットに制約
            ulong d0 = (r0 & BIT_26) * h0_c;
            ulong d1 = (r0 & BIT_26) * h1_c + (r1 & BIT_26) * h0_c;
            ulong d2 = (r0 & BIT_26) * h2_c + (r1 & BIT_26) * h1_c + (r2 & BIT_26) * h0_c;
            ulong d3 = (r0 & BIT_26) * h3_c + (r1 & BIT_26) * h2_c + (r2 & BIT_26) * h1_c + (r3 & BIT_26) * h0_c;
            ulong d4 = (r1 & BIT_26) * h3_c + (r2 & BIT_26) * h2_c + (r3 & BIT_26) * h1_c + (r4 & BIT_26) * h0_c;

            // 剰余計算: h = d mod (2^130 - 5)
            ulong s0 = d0;
            ulong s1 = d1 + (d0 >> 26);
            ulong s2 = d2 + (d1 >> 26) + (d0 >> 52);
            ulong s3 = d3 + (d2 >> 26) + (d1 >> 52) + (d0 >> 78);
            ulong s4 = d4 + (d3 >> 26) + (d2 >> 52) + (d1 >> 78);

            // モジュラス簡約
            (h0, h1, h2, h3) = Reduce1305(s0, s1, s2, s3, s4);
        }

        return (h0, h1, h2, h3);
    }

    /// <summary>2^130 - 5 での簡約。</summary>
    private static (uint, uint, uint, uint) Reduce1305(
        ulong a0, ulong a1, ulong a2, ulong a3, ulong a4 = 0)
    {
        // 26ビット制約定数
        const uint BIT_26 = 0x03FFFFFF; // 26ビットマスク

        ulong c = a0 >> 26;
        a0 &= BIT_26;

        ulong a0_plus = a0 + (c * 5);
        ulong carry = a0_plus >> 26;
        a0 = a0_plus & BIT_26;

        a1 += carry; carry = a1 >> 26; a1 &= BIT_26;
        a2 += carry; carry = a2 >> 26; a2 &= BIT_26;
        a3 += carry + a4; carry = a3 >> 26; a3 &= BIT_26;

        if (carry != 0)
        {
            a0 += 5;
            carry = a0 >> 26;
            a0 &= BIT_26;
            a1 += carry;
        }

        return ((uint)a0, (uint)a1, (uint)a2, (uint)a3);
    }
}

/// <summary>ChaCha20-XTS 暗号化モード実装。</summary>
public static class ChaCha20Xts
{
    private const int BlockSize = 16;
    private const int KeySize = 32;      // 256-bit マスターキー
    private const int XtsKeySize = 32;    // 256-bit (K1 or K2)

    /// <summary>ChaCha20-XTS ストリームを作成。</summary>
    public static Stream CreateChaCha20XtsStream(
        Stream baseStream, byte[] masterKey, long logicalLength, bool writable = true)
    {
        if (masterKey.Length != KeySize)
            throw new ArgumentException($"ChaCha20-XTS 鍵長は {KeySize} バイトである必要があります。", nameof(masterKey));

        // XTS キー生成 (K1, K2)
        byte[] k1 = HkdfSha256(masterKey, new byte[32], Encoding.UTF8.GetBytes("cista-xts-k1"), XtsKeySize);
        byte[] k2 = HkdfSha256(masterKey, new byte[32], Encoding.UTF8.GetBytes("cista-xts-k2"), XtsKeySize);

        return new ChaCha20XtsStream(baseStream, k1, k2, logicalLength, writable);
    }

    /// <summary>HKDF-SHA256 鍵導出。</summary>
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

/// <summary>ChaCha20-XTS ストリーム実装。</summary>
internal sealed class ChaCha20XtsStream : Stream
{
    private const int BlockSize = 16;
    private const int NonceSize = 12;

    private readonly Stream _base;
    private readonly byte[] _k1;  // K1 (データ暗号化鍵)
    private readonly byte[] _k2;  // K2 (トウィーク鍵)
    private long _length;
    private readonly bool _writable;

    private long _position;
    private bool disposed;

    public ChaCha20XtsStream(Stream baseStream, byte[] k1, byte[] k2, long logicalLength, bool writable)
    {
        _base = baseStream;
        _k1 = k1;
        _k2 = k2;
        _length = logicalLength;
        _writable = writable;
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => _writable;
    public override long Length => _length;
    public override long Position { get => _position; set => _position = value; }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (!CanRead || disposed)
            throw new InvalidOperationException("ストリームが読み取り不可能です。");

        if (_position >= _length) return 0;
        count = (int)Math.Min(count, _length - _position);

        int total = 0;
        while (count > 0)
        {
            // 16-byte ブロック単位で処理
            long blockIndex = _position / BlockSize;
            int offsetInBlock = (int)(_position % BlockSize);
            int readSize = Math.Min(BlockSize - offsetInBlock, count);

            // ブロック読み取り
            _base.Position = blockIndex * BlockSize;
            byte[] block = new byte[BlockSize];
            int bytesRead = _base.Read(block, 0, BlockSize);
            if (bytesRead == 0) break;

            // 読み込み不足部分はゼロ埋め
            if (bytesRead < BlockSize)
                Array.Clear(block, bytesRead, BlockSize - bytesRead);

            // ChaCha20-XTS 復号化
            DecryptXtsBlock(blockIndex, block);

            // コピー
            Array.Copy(block, offsetInBlock, buffer, offset, readSize);
            offset += readSize;
            _position += readSize;
            total += readSize;
            count -= readSize;

            if (bytesRead < BlockSize) break;
        }

        return total;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (!CanWrite || disposed)
            throw new InvalidOperationException("ストリームが書き込み不可能です。");

        while (count > 0)
        {
            long blockIndex = _position / BlockSize;
            int offsetInBlock = (int)(_position % BlockSize);
            int writeSize = Math.Min(BlockSize - offsetInBlock, count);

            // ブロック読み取り（Read-Modify-Write）
            _base.Position = blockIndex * BlockSize;
            byte[] block = new byte[BlockSize];
            int bytesRead = _base.Read(block, 0, BlockSize);
            if (bytesRead < BlockSize)
                Array.Clear(block, bytesRead, BlockSize - bytesRead);

            // 既存データを復号化（部分更新のため）
            if (offsetInBlock > 0 || writeSize < BlockSize)
            {
                byte[] tempBlock = (byte[])block.Clone();
                DecryptXtsBlock(blockIndex, tempBlock);
                tempBlock.CopyTo(block, 0);
            }

            // 新しいデータを書き込み
            Array.Copy(buffer, offset, block, offsetInBlock, writeSize);

            // ChaCha20-XTS 暗号化
            EncryptXtsBlock(blockIndex, block);

            // 書き戻し
            _base.Position = blockIndex * BlockSize;
            _base.Write(block, 0, BlockSize);

            offset += writeSize;
            _position += writeSize;
            count -= writeSize;
        }

        if (_position > _length) _length = _position;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        long newPosition = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        };
        if (newPosition < 0) throw new ArgumentOutOfRangeException(nameof(offset));
        return _position = newPosition;
    }

    public override void SetLength(long value)
    {
        if (!CanWrite) throw new NotSupportedException("読み取り専用ストリーム。");
        _length = value;
        _base.SetLength(value);
    }

    public override void Flush() => _base.Flush();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !disposed)
        {
            _base.Dispose();
            CryptographicOperations.ZeroMemory(_k1);
            CryptographicOperations.ZeroMemory(_k2);
            disposed = true;
        }
        base.Dispose(disposing);
    }

    /// <summary>XTS ブロック暗号化（RFC 7539 + IEEE 1619）。</summary>
    private void EncryptXtsBlock(long blockIndex, byte[] block)
    {
        // トウィーク値計算
        Span<byte> tweak = stackalloc byte[NonceSize];
        BinaryPrimitives.WriteInt64LittleEndian(tweak, blockIndex);

        // トウィーク暗号化（K2でChaCha20）
        Span<byte> encryptedTweak = stackalloc byte[BlockSize];
        byte[] tweakNonce = new byte[NonceSize];
        Array.Copy(tweak.ToArray(), 0, tweakNonce, 0, 8);
        ChaCha20Poly1305.ChaCha20Encrypt(_k2, tweakNonce, 0, encryptedTweak, encryptedTweak);

        // データ暗号化（K1でChaCha20）
        Span<byte> encryptedData = stackalloc byte[BlockSize];
        byte[] dataNonce = new byte[NonceSize];
        BinaryPrimitives.WriteInt32LittleEndian(dataNonce, (int)blockIndex);
        ChaCha20Poly1305.ChaCha20Encrypt(_k1, dataNonce, 0, encryptedData, block.AsSpan(0, BlockSize));

        // XTS: EncryptedData ⊕ Tweak
        for (int i = 0; i < BlockSize; i++)
        {
            block[i] = (byte)(encryptedData[i] ^ encryptedTweak[i]);
        }
    }

    /// <summary>XTS ブロック復号化。</summary>
    private void DecryptXtsBlock(long blockIndex, byte[] block)
    {
        // トウィーク値計算
        Span<byte> tweak = stackalloc byte[NonceSize];
        BinaryPrimitives.WriteInt64LittleEndian(tweak, blockIndex);

        // トウィーク暗号化
        Span<byte> encryptedTweak = stackalloc byte[BlockSize];
        byte[] tweakNonce = new byte[NonceSize];
        Array.Copy(tweak.ToArray(), 0, tweakNonce, 0, 8);
        ChaCha20Poly1305.ChaCha20Encrypt(_k2, tweakNonce, 0, encryptedTweak, encryptedTweak);

        // XTS: Block ⊕ Tweak
        Span<byte> xoredBlock = stackalloc byte[BlockSize];
        for (int i = 0; i < BlockSize; i++)
        {
            xoredBlock[i] = (byte)(block[i] ^ encryptedTweak[i]);
        }

        // データ復号化（K1でChaCha20）
        byte[] dataNonce = new byte[NonceSize];
        BinaryPrimitives.WriteInt32LittleEndian(dataNonce, (int)blockIndex);
        ChaCha20Poly1305.ChaCha20Decrypt(_k1, dataNonce, 0, xoredBlock, block.AsSpan(0, BlockSize));
    }
}
