using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace CistaNAS.Client.Crypto;

/// <summary>
/// ChaCha20 シーク可能ストリーム（RFC 7539）。
/// XTS モードは使用せず、カウンタ値を直接操作してシークを実現。
/// </summary>
internal sealed class ChaCha20Stream : Stream
{
    private const int KeySize = 32;        // 256-bit
    private const int NonceSize = 12;      // 96-bit
    private const int BlockSize = 64;      // ChaCha20 ブロックサイズ
    private const int SectorSize = 16;     // 暗号化単位（AES 互換）

    private readonly Stream _base;
    private readonly byte[] _key;
    private readonly byte[] _nonce;
    private long _length;
    private readonly bool _writable;

    private long _position;
    private bool disposed;

    public ChaCha20Stream(
        Stream baseStream,
        byte[] key,
        byte[] nonce,
        long logicalLength,
        bool writable = true)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"ChaCha20 鍵長は {KeySize} バイトである必要があります。", nameof(key));
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"ChaCha20 ノンスは {NonceSize} バイトである必要があります。", nameof(nonce));

        _base = baseStream;
        _key = key.ToArray();
        _nonce = nonce.ToArray();
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
        if (disposed)
            throw new ObjectDisposedException(nameof(ChaCha20Stream));
        if (!CanRead)
            throw new InvalidOperationException("ストリームが読み取り不可能です。");

        if (_position >= _length) return 0;
        count = (int)Math.Min(count, _length - _position);

        int total = 0;
        while (count > 0)
        {
            // セクタ単位で処理
            long sectorIndex = _position / SectorSize;
            int offsetInSector = (int)(_position % SectorSize);
            int readSize = Math.Min(SectorSize - offsetInSector, count);

            // セクタ読み取り
            long basePos = sectorIndex * SectorSize;
            _base.Position = basePos;
            byte[] sector = new byte[SectorSize];
            int bytesRead = _base.Read(sector, 0, SectorSize);
            if (bytesRead == 0) break;

            // 読み込み不足部分はゼロ埋め
            if (bytesRead < SectorSize)
                Array.Clear(sector, bytesRead, SectorSize - bytesRead);

            // ChaCha20 復号化（セクタインデックスをカウンタとして使用）
            ChaCha20DecryptSector(sector, sectorIndex);

            // コピー
            Array.Copy(sector, offsetInSector, buffer, offset, readSize);
            offset += readSize;
            _position += readSize;
            total += readSize;
            count -= readSize;

            if (bytesRead < SectorSize) break;
        }

        return total;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (disposed)
            throw new ObjectDisposedException(nameof(ChaCha20Stream));
        if (!CanWrite)
            throw new InvalidOperationException("ストリームが書き込み不可能です。");

        while (count > 0)
        {
            long sectorIndex = _position / SectorSize;
            int offsetInSector = (int)(_position % SectorSize);
            int writeSize = Math.Min(SectorSize - offsetInSector, count);

            // セクタ読み取り（Read-Modify-Write）
            long basePos = sectorIndex * SectorSize;
            _base.Position = basePos;
            byte[] sector = new byte[SectorSize];
            int bytesRead = _base.Read(sector, 0, SectorSize);
            if (bytesRead < SectorSize)
                Array.Clear(sector, bytesRead, SectorSize - bytesRead);

            // 既存データを復号化（部分更新のため）
            if (offsetInSector > 0 || writeSize < SectorSize)
            {
                byte[] tempSector = (byte[])sector.Clone();
                ChaCha20DecryptSector(tempSector, sectorIndex);
                tempSector.CopyTo(sector, 0);
            }

            // 新しいデータを書き込み
            Array.Copy(buffer, offset, sector, offsetInSector, writeSize);

            // ChaCha20 暗号化
            ChaCha20EncryptSector(sector, sectorIndex);

            // 書き戻し
            _base.Position = basePos;
            _base.Write(sector, 0, SectorSize);

            offset += writeSize;
            _position += writeSize;
            count -= writeSize;
        }

        if (_position > _length) _length = _position;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        if (disposed)
            throw new ObjectDisposedException(nameof(ChaCha20Stream));

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
        if (disposed)
            throw new ObjectDisposedException(nameof(ChaCha20Stream));
        if (!CanWrite)
            throw new NotSupportedException("読み取り専用ストリーム。");

        // サイズ縮小時は基礎ストリームを縮小
        if (value < _length)
        {
            _base.SetLength(value);
        }
        // サイズ拡張時は基礎ストリームの新しい部分を暗号化されたゼロで埋める
        else if (value > _length)
        {
            _base.SetLength(value);

            // 拡張部分をセクタ単位で暗号化されたゼロで埋める
            long oldSectorCount = (_length + SectorSize - 1) / SectorSize;
            long newSectorCount = (value + SectorSize - 1) / SectorSize;

            for (long sectorIndex = oldSectorCount; sectorIndex < newSectorCount; sectorIndex++)
            {
                long basePos = sectorIndex * SectorSize;
                int sectorLength = (int)Math.Min(SectorSize, value - basePos);

                // ゼロセクタを準備
                byte[] zeroSector = new byte[SectorSize];

                // ChaCha20 暗号化
                ChaCha20EncryptSector(zeroSector, sectorIndex);

                // 書き込み
                _base.Position = basePos;
                _base.Write(zeroSector, 0, sectorLength);
            }
        }
        _length = value;
    }

    public override void Flush() => _base.Flush();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !disposed)
        {
            _base.Dispose();
            CryptographicOperations.ZeroMemory(_key);
            CryptographicOperations.ZeroMemory(_nonce);
            disposed = true;
        }
        base.Dispose(disposing);
    }

    /// <summary>セクタ単位で ChaCha20 暗号化。</summary>
    private void ChaCha20EncryptSector(byte[] sector, long sectorIndex)
    {
        // セクタインデックスをカウンタとして使用
        // セクタサイズがブロックサイズより小さいため、セクタインデックスをそのままカウンタとして使用
        uint counter = (uint)sectorIndex;
        ChaCha20Encrypt(_key, _nonce, counter, sector);
    }

    /// <summary>セクタ単位で ChaCha20 復号化。</summary>
    private void ChaCha20DecryptSector(byte[] sector, long sectorIndex)
    {
        // ChaCha20 は XOR 暗号なので暗号化と復号化は同じ
        ChaCha20EncryptSector(sector, sectorIndex);
    }

    /// <summary>ChaCha20 暗号化（RFC 7539）。</summary>
    private void ChaCha20Encrypt(byte[] key, byte[] nonce, uint counter, byte[] data)
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
            int blockSize = Math.Min(BlockSize, byteCount);
            for (int i = 0; i < blockSize; i++)
            {
                int wordIndex = i / 4;
                int byteInWord = i % 4;
                uint keyByte = (keyStream[wordIndex] >> (byteInWord * 8)) & 0xFF;
                data[blockIndex * BlockSize + i] ^= (byte)keyByte;
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
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRound(uint[] x, int a, int b, int c, int d)
    {
        x[a] += x[d]; x[b] = RotateLeft(x[b] ^ x[a], 16);
        x[c] += x[b]; x[d] = RotateLeft(x[d] ^ x[c], 12);
        x[a] += x[d]; x[b] = RotateLeft(x[b] ^ x[a], 8);
        x[c] += x[b]; x[d] = RotateLeft(x[d] ^ x[c], 7);
    }

    /// <summary>左ローテート。</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint RotateLeft(uint value, int count)
        => (value << count) | (value >> (32 - count));
}
