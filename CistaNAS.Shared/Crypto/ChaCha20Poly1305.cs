using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace CistaNAS.Shared.Crypto;

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

    /// <summary>Poly1305 タグ生成（RFC 7539 §2.5 準拠、poly1305-donna 5-limb 26-bit 実装）。</summary>
    private static byte[] Poly1305ComputeTag(byte[] key, byte[] nonce, byte[] ciphertext)
    {
        // Poly1305 1-time key: ChaCha20(counter=0) の最初の 32 バイト
        byte[] polyKey = new byte[32];
        ChaCha20Encrypt(key, nonce, 0, polyKey, polyKey);

        // r の抽出（poly1305-donna クランピング: r &= 0xffffffc0ffffffc0ffffffc0fffffff）
        uint r0 = BinaryPrimitives.ReadUInt32LittleEndian(polyKey.AsSpan(0)) & 0x03FFFFFF;
        uint r1 = (BinaryPrimitives.ReadUInt32LittleEndian(polyKey.AsSpan(3)) >> 2) & 0x03FFFF03;
        uint r2 = (BinaryPrimitives.ReadUInt32LittleEndian(polyKey.AsSpan(6)) >> 4) & 0x03FFC0FF;
        uint r3 = (BinaryPrimitives.ReadUInt32LittleEndian(polyKey.AsSpan(9)) >> 6) & 0x03F03FFF;
        uint r4 = (BinaryPrimitives.ReadUInt32LittleEndian(polyKey.AsSpan(12)) >> 8) & 0x000FFFFF;

        // s (32 バイトのうち r 以降の 16 バイト)
        uint s0 = BinaryPrimitives.ReadUInt32LittleEndian(polyKey.AsSpan(16));
        uint s1 = BinaryPrimitives.ReadUInt32LittleEndian(polyKey.AsSpan(20));
        uint s2 = BinaryPrimitives.ReadUInt32LittleEndian(polyKey.AsSpan(24));
        uint s3 = BinaryPrimitives.ReadUInt32LittleEndian(polyKey.AsSpan(28));

        // Poly1305 コア (5 リム 130-bit)
        (uint h0, uint h1, uint h2, uint h3, uint h4) = Poly1305Core(ciphertext, r0, r1, r2, r3, r4);

        // 最終キャリー (h を完全正規化: 各 limb 26-bit)
        uint carry = h1 >> 26; h1 &= 0x03FFFFFF;
        h2 += carry;        carry = h2 >> 26; h2 &= 0x03FFFFFF;
        h3 += carry;        carry = h3 >> 26; h3 &= 0x03FFFFFF;
        h4 += carry;        carry = h4 >> 26; h4 &= 0x03FFFFFF;
        h0 += carry * 5;    carry = h0 >> 26; h0 &= 0x03FFFFFF;
        h1 += carry;

        // mod 2^130-5: h >= 2^130-5 なら h - (2^130-5) = h + 5 - 2^130 を使う。
        // h + 5 を計算し、h4 のオーバーフローで元の h が 2^130-5 以上だったかを判定。
        uint g0 = h0 + 5;
        carry = g0 >> 26; g0 &= 0x03FFFFFF;
        uint g1 = h1 + carry;
        carry = g1 >> 26; g1 &= 0x03FFFFFF;
        uint g2 = h2 + carry;
        carry = g2 >> 26; g2 &= 0x03FFFFFF;
        uint g3 = h3 + carry;
        carry = g3 >> 26; g3 &= 0x03FFFFFF;
        uint g4 = h4 + carry - (1u << 26);

        // g4 の最上位ビットで g を使うか h を使うかを判定（タイミング攻撃回避）。
        // g4 high bit = 0 → h < p → g を使う
        // g4 high bit = 1 → h >= p → h を使う
        uint g4HighBit = g4 >> 31;  // 0 or 1
        uint mask = g4HighBit - 1u;  // 0xFFFFFFFF if h < p, 0 if h >= p
        h0 = (h0 & ~mask) | (g0 & mask);
        h1 = (h1 & ~mask) | (g1 & mask);
        h2 = (h2 & ~mask) | (g2 & mask);
        h3 = (h3 & ~mask) | (g3 & mask);
        // h4 も同様に選択 (donna-32 準拠、後段の repack で h4 << 8 が h3 の high バイトに伝播するため)
        h4 = (h4 & ~mask) | ((g4 + (1u << 26)) & mask);  // g4 = h4 - 2^26 だったので元に戻す

        // 5 リム 26-bit を 4 リム 32-bit に repack (poly1305-donna と同じ)
        //   h0_32 = h0 | (h1 << 26)         ; h1 は 26-bit なので (h1 << 26) の下位 32 bit = h1 の下位 6 bit
        //   h1_32 = (h1 >> 6) | (h2 << 20)
        //   h2_32 = (h2 >> 12) | (h3 << 14)
        //   h3_32 = (h3 >> 18) | (h4 << 8)
        h0 = (h0 | (h1 << 26)) & 0xFFFFFFFF;
        h1 = ((h1 >> 6) | (h2 << 20)) & 0xFFFFFFFF;
        h2 = ((h2 >> 12) | (h3 << 14)) & 0xFFFFFFFF;
        h3 = ((h3 >> 18) | (h4 << 8)) & 0xFFFFFFFF;

        // s を加算 (mod 2^128)
        ulong f = (ulong)h0 + s0;             h0 = (uint)f;
        f = ((ulong)h1 + s1) + (f >> 32);    h1 = (uint)f;
        f = ((ulong)h2 + s2) + (f >> 32);    h2 = (uint)f;
        f = ((ulong)h3 + s3) + (f >> 32);    h3 = (uint)f;
        // h4 のオーバーフロー（もしあれば）は 2^130 ≡ 5 で 2^128 mod 2^130-5 側に折り畳まれるが、
        // タグは下位 128 bit だけなので捨てる。

        // タグ生成（リトルエンディアン 16 バイト）
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

    /// <summary>
    /// 任意バイト列に対する Poly1305 タグ計算（公開）。
    /// E2eeCrypto.EncryptChunkChaCha20 等で AAD を含む mac_data のタグ計算に使用する。
    /// </summary>
    internal static byte[] ComputePoly1305Tag(byte[] key, byte[] nonce, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(nonce);
        ArgumentNullException.ThrowIfNull(data);
        return Poly1305ComputeTag(key, nonce, data);
    }

    /// <summary>
    /// 任意バイト列に対する Poly1305 タグ検証（公開、定数時間比較）。
    /// </summary>
    internal static bool VerifyPoly1305Tag(byte[] key, byte[] nonce, byte[] data, byte[] tag)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(nonce);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(tag);
        return Poly1305VerifyTag(key, nonce, data, tag);
    }

    /// <summary>
    /// Poly1305 コア: 16 バイトブロック単位で (h + c) * r mod (2^130 - 5) を計算。
    /// poly1305-donna と同じ 5 リム 26-bit limbs 表現。
    /// <para>
    /// 重要な仕様 (poly1305-donna / RFC 8439 §2.5):
    /// ・非最終ブロック: 16 バイトのデータ + 2^128 (HIBIT) を加算
    /// ・最終ブロック (partial): データ + 0x01 パディング + 0、2^128 は加算しない
    /// </para>
    /// </summary>
    private static (uint h0, uint h1, uint h2, uint h3, uint h4) Poly1305Core(
        byte[] data, uint r0, uint r1, uint r2, uint r3, uint r4)
    {
        const uint BIT_26 = 0x03FFFFFF;
        const uint HIBIT  = 1u << 24;  // 5 リム目への 2^128 マーカー（非最終ブロックのみ）
        const int PolyBlock = 16;

        uint h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

        // 事前計算: s_i = r_i * 5（mod (2^130 - 5) 還元の効率化）
        uint s1 = r1 * 5;
        uint s2 = r2 * 5;
        uint s3 = r3 * 5;
        uint s4 = r4 * 5;

        int offset = 0;
        int length = data.Length;

        // ループ外の固定サイズバッファで stackalloc を一度だけ行う
        Span<byte> block = stackalloc byte[PolyBlock];

        while (length > 0)
        {
            int blockSize = Math.Min(PolyBlock, length);

            // 16 バイトブロックを構築
            block.Clear();
            data.AsSpan(offset, blockSize).CopyTo(block);

            // フルブロック（16B）には hibit(2^128) を c4 に加算（最終・中間問わず）。
            // partial ブロック（最終のみ到達可能）は末尾 0x01 を付加し hibit は加えない
            // （RFC 8439 §2.5 / poly1305-donna 準拠）。
            bool isFullBlock = blockSize == PolyBlock;
            if (!isFullBlock)
                block[blockSize] = 0x01;

            // リトルエンディアン 5 リム 26-bit (poly1305-donna の bit 配置と一致)
            uint c0 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(0, 4)) & BIT_26;
            uint c1 = (BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(3, 4)) >> 2) & BIT_26;
            uint c2 = (BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(6, 4)) >> 4) & BIT_26;
            uint c3 = (BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(9, 4)) >> 6) & BIT_26;
            // フルブロックは HIBIT(2^128) を加算。partial ブロックは 0x01 パディングのみ。
            uint c4 = isFullBlock
                ? (BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(12, 4)) >> 8) | HIBIT
                : (BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(12, 4)) >> 8);

            offset += blockSize;
            length -= blockSize;

            // h += c
            h0 += c0; h1 += c1; h2 += c2; h3 += c3; h4 += c4;

            // h *= r（poly1305-donna 方式: s_i = r_i * 5 で 2^130 ≡ 5 の還元を組み込む）
            ulong d0 = (ulong)h0 * r0 + (ulong)h1 * s4 + (ulong)h2 * s3 + (ulong)h3 * s2 + (ulong)h4 * s1;
            ulong d1 = (ulong)h0 * r1 + (ulong)h1 * r0 + (ulong)h2 * s4 + (ulong)h3 * s3 + (ulong)h4 * s2;
            ulong d2 = (ulong)h0 * r2 + (ulong)h1 * r1 + (ulong)h2 * r0 + (ulong)h3 * s4 + (ulong)h4 * s3;
            ulong d3 = (ulong)h0 * r3 + (ulong)h1 * r2 + (ulong)h2 * r1 + (ulong)h3 * r0 + (ulong)h4 * s4;
            ulong d4 = (ulong)h0 * r4 + (ulong)h1 * r3 + (ulong)h2 * r2 + (ulong)h3 * r1 + (ulong)h4 * r0;

            // 部分還元 (各 limb 26-bit に)
            uint c = (uint)(d0 >> 26); h0 = (uint)(d0 & BIT_26);
            d1 += c;        c = (uint)(d1 >> 26); h1 = (uint)(d1 & BIT_26);
            d2 += c;        c = (uint)(d2 >> 26); h2 = (uint)(d2 & BIT_26);
            d3 += c;        c = (uint)(d3 >> 26); h3 = (uint)(d3 & BIT_26);
            d4 += c;        c = (uint)(d4 >> 26); h4 = (uint)(d4 & BIT_26);

            // 2^130 ≡ 5 (mod 2^130 - 5) 還元の最終段
            h0 += c * 5;
            c = h0 >> 26; h0 &= BIT_26;
            h1 += c;       c = h1 >> 26; h1 &= BIT_26;
            h2 += c;       c = h2 >> 26; h2 &= BIT_26;
            h3 += c;       c = h3 >> 26; h3 &= BIT_26;
            h4 += c;
        }

        return (h0, h1, h2, h3, h4);
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
        // 注: dataNonce は 96-bit = 12 バイトだが blockIndex は long (64-bit)。
        //     下位 8 バイトを little-endian で書き込み、上位 4 バイトはゼロ固定
        //     （ドメインベクタとして 0xc1a5 を入れることで、tweak 側との衝突を防ぐ）。
        Span<byte> encryptedData = stackalloc byte[BlockSize];
        byte[] dataNonce = new byte[NonceSize];
        BinaryPrimitives.WriteInt64LittleEndian(dataNonce.AsSpan(0, 8), blockIndex);
        BinaryPrimitives.WriteUInt16LittleEndian(dataNonce.AsSpan(8, 2), 0xc1a5);  // ドメイン分離タグ
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
        // 注: EncryptXtsBlock と対称: blockIndex の全 64 ビットを使用し、ドメインベクタも同一。
        byte[] dataNonce = new byte[NonceSize];
        BinaryPrimitives.WriteInt64LittleEndian(dataNonce.AsSpan(0, 8), blockIndex);
        BinaryPrimitives.WriteUInt16LittleEndian(dataNonce.AsSpan(8, 2), 0xc1a5);  // ドメイン分離タグ
        ChaCha20Poly1305.ChaCha20Decrypt(_k1, dataNonce, 0, xoredBlock, block.AsSpan(0, BlockSize));
    }
}
