using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CistaNAS.Shared.Crypto;

/// <summary>
/// IEEE 1619 / NIST SP 800-38E の XTS-AES によるシーク可能な暗号化ストリーム。
/// 低レベル実装。Volume / File 層から呼ばれる。
/// </summary>
/// <remarks>
/// <para>基底ストリームには「暗号化データ領域のみ」を渡す（ボリュームヘッダは含めない）。</para>
/// <para>
/// 平文の論理長は呼び出し側（ボリュームのファイルメタデータ）が保持する。
/// ディスク上は <c>sectorSize</c> 単位にゼロパディングして格納するため、
/// 端数ブロックの ciphertext stealing は不要（NAS 用途で一般的な設計）。
/// </para>
/// <para>各セクタを 1 つのデータユニットとし、データユニット番号＝セクタ索引。</para>
/// </remarks>
public sealed class AesXtsStream : Stream
{
    private const int BlockSize = 16;

    private readonly Stream _base;
    private readonly bool _leaveOpen;
    private readonly int _sectorSize;
    private readonly Aes _dataAes;   // K1: データ暗号化
    private readonly Aes _tweakAes;  // K2: トウィーク暗号化
    private readonly ICryptoTransform _dataEnc;
    private readonly ICryptoTransform _dataDec;
    private readonly ICryptoTransform _tweakEnc;

    private long _length;
    private long _position;
    private bool _disposed;

    public AesXtsStream(
        Stream baseStream,
        ReadOnlySpan<byte> key,
        int sectorSize,
        long logicalLength,
        bool writable,
        bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(baseStream);
        if (key.Length != KeyDerivation.MasterKeySize)
            throw new ArgumentException("AES-256-XTS の鍵は 64 バイト（K1||K2）。", nameof(key));
        if (sectorSize <= 0 || sectorSize % BlockSize != 0)
            throw new ArgumentException("セクタサイズは 16 の倍数であること。", nameof(sectorSize));
        if (logicalLength < 0)
            throw new ArgumentOutOfRangeException(nameof(logicalLength));

        _base = baseStream;
        _leaveOpen = leaveOpen;
        _sectorSize = sectorSize;
        _length = logicalLength;
        CanWrite = writable;

        _dataAes = Aes.Create();
        _dataAes.Mode = CipherMode.ECB;
        _dataAes.Padding = PaddingMode.None;
        _dataAes.Key = key[..32].ToArray();

        _tweakAes = Aes.Create();
        _tweakAes.Mode = CipherMode.ECB;
        _tweakAes.Padding = PaddingMode.None;
        _tweakAes.Key = key[32..].ToArray();

        _dataEnc = _dataAes.CreateEncryptor();
        _dataDec = _dataAes.CreateDecryptor();
        _tweakEnc = _tweakAes.CreateEncryptor();
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite { get; }
    public override long Length => _length;

    public override long Position
    {
        get => _position;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _position = value;
        }
    }

    // ---- XTS コア ----

    /// <summary>GF(2^128) での α 倍（多項式 x^128+x^7+x^2+x+1, リトルエンディアン）。</summary>
    private static void MultiplyAlpha(Span<byte> t)
    {
        int carry = 0;
        for (int i = 0; i < BlockSize; i++)
        {
            int b = t[i];
            int next = (b >> 7) & 1;
            t[i] = (byte)((b << 1) | carry);
            carry = next;
        }
        if (carry != 0) t[0] ^= 0x87;
    }

    private void ComputeTweak(long sectorIndex, Span<byte> tweak)
    {
        // TransformBlock requires byte[], so use direct byte[] instead of stackalloc+ToArray
        byte[] inBuf = new byte[BlockSize];
        byte[] outBuf = new byte[BlockSize];
        BinaryPrimitives.WriteUInt64LittleEndian(inBuf, (ulong)sectorIndex);
        _tweakEnc.TransformBlock(inBuf, 0, BlockSize, outBuf, 0);
        ((Span<byte>)outBuf).CopyTo(tweak);
    }

    /// <summary>セクタ（=データユニット）を in-place で暗号化/復号する。</summary>
    private void TransformSector(long sectorIndex, Span<byte> data, bool encrypt)
    {
        if (data.Length % BlockSize != 0)
            throw new ArgumentException("セクタ長は 16 の倍数であること。", nameof(data));

        Span<byte> t = stackalloc byte[BlockSize];
        ComputeTweak(sectorIndex, t);

        ICryptoTransform cipher = encrypt ? _dataEnc : _dataDec;
        byte[] tmpIn = new byte[BlockSize];
        byte[] tmpOut = new byte[BlockSize];

        for (int off = 0; off < data.Length; off += BlockSize)
        {
            Span<byte> blk = data.Slice(off, BlockSize);
            for (int i = 0; i < BlockSize; i++) tmpIn[i] = (byte)(blk[i] ^ t[i]);
            cipher.TransformBlock(tmpIn, 0, BlockSize, tmpOut, 0);
            for (int i = 0; i < BlockSize; i++) blk[i] = (byte)(tmpOut[i] ^ t[i]);
            MultiplyAlpha(t);
        }
    }

    // ---- セクタ I/O ----

    private async Task ReadSectorPlainAsync(long sectorIndex, Memory<byte> sector, CancellationToken ct)
    {
        long pos = sectorIndex * _sectorSize;
        if (pos >= _base.Length)
        {
            sector.Span.Clear();
            return;
        }

        _base.Position = pos;
        int read = 0;
        byte[] buf = new byte[_sectorSize];
        while (read < _sectorSize)
        {
            int n = await _base.ReadAsync(buf.AsMemory(read, _sectorSize - read), ct).ConfigureAwait(false);
            if (n == 0) break;
            read += n;
        }
        if (read < _sectorSize) Array.Clear(buf, read, _sectorSize - read);
        buf.CopyTo(sector.Span);
        TransformSector(sectorIndex, sector.Span, encrypt: false);
    }

    private void ReadSectorPlain(long sectorIndex, Span<byte> sector)
    {
        long pos = sectorIndex * _sectorSize;
        if (pos >= _base.Length)
        {
            sector.Clear();
            return;
        }

        _base.Position = pos;
        int read = 0;
        byte[] buf = new byte[_sectorSize];
        while (read < _sectorSize)
        {
            int n = _base.Read(buf, read, _sectorSize - read);
            if (n == 0) break;
            read += n;
        }
        if (read < _sectorSize) Array.Clear(buf, read, _sectorSize - read);
        buf.CopyTo(sector);
        TransformSector(sectorIndex, sector, encrypt: false);
    }

    private async Task WriteSectorPlainAsync(long sectorIndex, ReadOnlyMemory<byte> plain, CancellationToken ct)
    {
        byte[] enc = plain.ToArray();
        TransformSector(sectorIndex, enc, encrypt: true);
        _base.Position = sectorIndex * _sectorSize;
        await _base.WriteAsync(enc.AsMemory(0, enc.Length), ct).ConfigureAwait(false);
    }

    private void WriteSectorPlain(long sectorIndex, Span<byte> plain)
    {
        byte[] enc = plain.ToArray();
        TransformSector(sectorIndex, enc, encrypt: true);
        _base.Position = sectorIndex * _sectorSize;
        _base.Write(enc, 0, enc.Length);
    }

    // ---- Stream ----

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_position >= _length) return 0;
        count = (int)Math.Min(count, _length - _position);
        int total = 0;
        byte[] sector = new byte[_sectorSize];

        while (count > 0)
        {
            long si = _position / _sectorSize;
            int sOff = (int)(_position % _sectorSize);
            ReadSectorPlain(si, sector);
            int n = Math.Min(count, _sectorSize - sOff);
            Buffer.BlockCopy(sector, sOff, buffer, offset, n);
            offset += n;
            _position += n;
            total += n;
            count -= n;
        }
        return total;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_position >= _length) return 0;
        int count = (int)Math.Min(buffer.Length, _length - _position);
        int total = 0;

        while (count > 0)
        {
            long si = _position / _sectorSize;
            int sOff = (int)(_position % _sectorSize);
            byte[] sector = new byte[_sectorSize];
            await ReadSectorPlainAsync(si, sector.AsMemory(), cancellationToken).ConfigureAwait(false);
            int n = Math.Min(count, _sectorSize - sOff);
            sector.AsSpan(sOff, n).CopyTo(buffer.Span);
            buffer = buffer[n..];
            _position += n;
            total += n;
            count -= n;
        }
        return total;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!CanWrite) throw new NotSupportedException("読み取り専用ストリーム。");

        ReadOnlySpan<byte> src = buffer.AsSpan(offset, count);
        byte[] sector = new byte[_sectorSize];

        while (!src.IsEmpty)
        {
            long si = _position / _sectorSize;
            int sOff = (int)(_position % _sectorSize);
            int n = Math.Min(src.Length, _sectorSize - sOff);
            bool full = sOff == 0 && n == _sectorSize;

            if (full)
                Array.Clear(sector);
            else
                ReadSectorPlain(si, sector); // RMW: 既存セクタを復号して部分更新

            src[..n].CopyTo(sector.AsSpan(sOff));
            WriteSectorPlain(si, sector);

            _position += n;
            if (_position > _length) _length = _position;
            src = src[n..];
        }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!CanWrite) throw new NotSupportedException("読み取り専用ストリーム。");

        ReadOnlyMemory<byte> src = buffer;
        byte[] sector = new byte[_sectorSize];

        while (!src.IsEmpty)
        {
            long si = _position / _sectorSize;
            int sOff = (int)(_position % _sectorSize);
            int n = Math.Min(src.Length, _sectorSize - sOff);
            bool full = sOff == 0 && n == _sectorSize;

            if (full)
                Array.Clear(sector);
            else
                await ReadSectorPlainAsync(si, sector.AsMemory(), cancellationToken).ConfigureAwait(false); // RMW: 既存セクタを復号して部分更新

            src.Span[..n].CopyTo(sector.AsSpan(sOff));
            await WriteSectorPlainAsync(si, sector.AsMemory(0, _sectorSize), cancellationToken).ConfigureAwait(false);

            _position += n;
            if (_position > _length) _length = _position;
            src = src[n..];
        }
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(AesXtsStream));

        long target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        ArgumentOutOfRangeException.ThrowIfNegative(target, nameof(offset));
        _position = target;
        return _position;
    }

    public override void SetLength(long value)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(AesXtsStream));

        ArgumentOutOfRangeException.ThrowIfNegative(value);
        if (!CanWrite) throw new NotSupportedException();

        long oldSectors = (_length + _sectorSize - 1) / _sectorSize;
        _length = value;
        long newSectors = (value + _sectorSize - 1) / _sectorSize;

        // 拡張時は新しいセクタを暗号化されたゼロで埋める
        if (newSectors > oldSectors)
        {
            _base.SetLength(newSectors * _sectorSize);

            byte[] zeroSector = new byte[_sectorSize];
            for (long si = oldSectors; si < newSectors; si++)
            {
                WriteSectorPlain(si, zeroSector);
            }
        }
        else
        {
            _base.SetLength(newSectors * _sectorSize);
        }
    }

    public override void Flush() => _base.Flush();

    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        if (disposing)
        {
            _dataEnc.Dispose();
            _dataDec.Dispose();
            _tweakEnc.Dispose();
            // 暗号鍵のメモリゼロ化
            CryptographicOperations.ZeroMemory(_dataAes.Key);
            CryptographicOperations.ZeroMemory(_tweakAes.Key);
            _dataAes.Dispose();
            _tweakAes.Dispose();
            if (!_leaveOpen) _base.Dispose();
        }
        _disposed = true;
        base.Dispose(disposing);
    }
}
