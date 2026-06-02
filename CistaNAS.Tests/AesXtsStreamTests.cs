using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// クライアント側 AesXtsStream の単体テスト。
/// AES-XTS ストリームの読み取り・書き込み・シーク・部分更新などの動作を検証。
/// </summary>
public class AesXtsStreamTests
{
    private const int SectorSize = 4096; // 通常のセクタサイズ

    /// <summary>
    /// テスト用 AesXtsStream を作成。
    /// </summary>
    private static (AesXtsStreamImpl stream, MemoryStream baseStream, byte[] key) CreateStream(long length, bool writable = true)
    {
        var baseStream = new MemoryStream();
        // 基礎ストリームを十分に確保
        baseStream.SetLength(length + SectorSize);

        byte[] key = RandomNumberGenerator.GetBytes(64); // AES-XTS は 64 バイト (K1 + K2)

        var stream = new AesXtsStreamImpl(baseStream, key, SectorSize, length, writable);
        return (stream, baseStream, key);
    }

    /// <summary>
    /// AesXtsStream の内部実装クラス（テスト用）。
    /// </summary>
    private sealed class AesXtsStreamImpl : Stream
    {
        private readonly Stream _base;

        public AesXtsStreamImpl(Stream baseStream, byte[] key, int sectorSize, long logicalLength, bool writable, bool leaveOpen = false)
        {
            // CistaNAS.Shared.Crypto.AesXtsStream (旧 Client 側) の static factory CreateAesXtsStream は
            // 重複実装の整理 (Phase 2) で削除された。Web 側 AesXtsStream のコンストラクタを直接使う。
            _base = new AesXtsStream(baseStream, key, sectorSize, logicalLength, writable, leaveOpen);
        }

        public override bool CanRead => _base.CanRead;
        public override bool CanSeek => _base.CanSeek;
        public override bool CanWrite => _base.CanWrite;
        public override long Length => _base.Length;
        public override long Position { get => _base.Position; set => _base.Position = value; }

        public override int Read(byte[] buffer, int offset, int count)
            => _base.Read(buffer, offset, count);

        public override void Write(byte[] buffer, int offset, int count)
            => _base.Write(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin)
            => _base.Seek(offset, origin);

        public override void SetLength(long value)
            => _base.SetLength(value);

        public override void Flush()
            => _base.Flush();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _base.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    [Fact]
    public void Read_SingleSector_Roundtrip()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(SectorSize);
        var (stream, baseStream, key) = CreateStream(SectorSize);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        stream.Seek(0, SeekOrigin.Begin);
        byte[] decrypted = new byte[SectorSize];
        int bytesRead = stream.Read(decrypted, 0, decrypted.Length);

        Assert.Equal(SectorSize, bytesRead);
        Assert.Equal(plain, decrypted);
        stream.Dispose();
    }

    [Fact]
    public void Read_MultipleSectors_Roundtrip()
    {
        int size = SectorSize * 10;
        byte[] plain = RandomNumberGenerator.GetBytes(size);
        var (stream, baseStream, key) = CreateStream(size);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        stream.Seek(0, SeekOrigin.Begin);
        byte[] decrypted = new byte[size];
        int totalRead = 0;
        while (totalRead < size)
        {
            int n = stream.Read(decrypted, totalRead, size - totalRead);
            if (n == 0) break;
            totalRead += n;
        }

        Assert.Equal(size, totalRead);
        Assert.Equal(plain, decrypted);
        stream.Dispose();
    }

    [Fact]
    public void Read_PartialSector_Roundtrip()
    {
        int size = SectorSize - 100;
        byte[] plain = RandomNumberGenerator.GetBytes(size);
        var (stream, baseStream, key) = CreateStream(SectorSize);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        stream.Seek(0, SeekOrigin.Begin);
        byte[] decrypted = new byte[size];
        int bytesRead = stream.Read(decrypted, 0, decrypted.Length);

        Assert.Equal(size, bytesRead);
        Assert.Equal(plain, decrypted);
        stream.Dispose();
    }

    [Fact]
    public void Seek_AbsolutePosition_ReadsCorrectly()
    {
        int size = SectorSize * 5;
        byte[] plain = RandomNumberGenerator.GetBytes(size);
        var (stream, baseStream, key) = CreateStream(size);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        int seekPos = SectorSize * 2;
        stream.Seek(seekPos, SeekOrigin.Begin);
        Assert.Equal(seekPos, stream.Position);

        byte[] decrypted = new byte[SectorSize];
        stream.Read(decrypted, 0, decrypted.Length);

        byte[] expected = plain[seekPos..(seekPos + SectorSize)];
        Assert.Equal(expected, decrypted);
        stream.Dispose();
    }

    [Fact]
    public void Seek_RelativePosition_WorksCorrectly()
    {
        int size = SectorSize * 3;
        byte[] plain = RandomNumberGenerator.GetBytes(size);
        var (stream, baseStream, key) = CreateStream(size);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        stream.Seek(0, SeekOrigin.Begin);
        Assert.Equal(0, stream.Position);

        stream.Seek(SectorSize, SeekOrigin.Current);
        Assert.Equal(SectorSize, stream.Position);

        byte[] decrypted = new byte[SectorSize];
        stream.Read(decrypted, 0, decrypted.Length);

        byte[] expected = plain[SectorSize..(SectorSize * 2)];
        Assert.Equal(expected, decrypted);
        stream.Dispose();
    }

    [Fact]
    public void Seek_FromEnd_WorksCorrectly()
    {
        int size = SectorSize * 4;
        byte[] plain = RandomNumberGenerator.GetBytes(size);
        var (stream, baseStream, key) = CreateStream(size);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        stream.Seek(-SectorSize, SeekOrigin.End);
        Assert.Equal(size - SectorSize, stream.Position);

        byte[] decrypted = new byte[SectorSize];
        stream.Read(decrypted, 0, decrypted.Length);

        byte[] expected = plain[(size - SectorSize)..size];
        Assert.Equal(expected, decrypted);
        stream.Dispose();
    }

    [Fact]
    public void Write_PartialSector_Update_WorksCorrectly()
    {
        int size = SectorSize * 2;
        byte[] plain = RandomNumberGenerator.GetBytes(size);
        var (stream, baseStream, key) = CreateStream(size);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        int updateOffset = SectorSize + 500;
        int updateSize = 200;
        byte[] updateData = RandomNumberGenerator.GetBytes(updateSize);

        stream.Seek(updateOffset, SeekOrigin.Begin);
        stream.Write(updateData, 0, updateSize);
        stream.Flush();

        stream.Seek(updateOffset, SeekOrigin.Begin);
        byte[] readBack = new byte[updateSize];
        stream.Read(readBack, 0, readBack.Length);

        Assert.Equal(updateData, readBack);

        stream.Seek(0, SeekOrigin.Begin);
        byte[] decrypted = new byte[size];
        int totalRead = 0;
        while (totalRead < size)
        {
            int n = stream.Read(decrypted, totalRead, size - totalRead);
            if (n == 0) break;
            totalRead += n;
        }

        Assert.Equal(plain[..updateOffset], decrypted[..updateOffset]);
        Assert.Equal(updateData, decrypted[updateOffset..(updateOffset + updateSize)]);
        Assert.Equal(plain[(updateOffset + updateSize)..], decrypted[(updateOffset + updateSize)..]);
        stream.Dispose();
    }

    [Fact]
    public void Write_CrossSectorBoundary_WorksCorrectly()
    {
        int size = SectorSize * 3;
        var (stream, baseStream, key) = CreateStream(size);

        int writeOffset = SectorSize - 100;
        int writeSize = SectorSize + 200;
        byte[] writeData = RandomNumberGenerator.GetBytes(writeSize);

        stream.Seek(writeOffset, SeekOrigin.Begin);
        stream.Write(writeData, 0, writeSize);
        stream.Flush();

        stream.Seek(writeOffset, SeekOrigin.Begin);
        byte[] readBack = new byte[writeSize];
        int totalRead = 0;
        while (totalRead < writeSize)
        {
            int n = stream.Read(readBack, totalRead, writeSize - totalRead);
            if (n == 0) break;
            totalRead += n;
        }

        Assert.Equal(writeData, readBack);
        stream.Dispose();
    }

    [Fact]
    public void SetLength_TruncatesFile()
    {
        int originalSize = SectorSize * 5;
        byte[] plain = RandomNumberGenerator.GetBytes(originalSize);
        var (stream, baseStream, key) = CreateStream(originalSize);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        int newSize = SectorSize * 2;
        stream.SetLength(newSize);
        Assert.Equal(newSize, stream.Length);

        stream.Seek(0, SeekOrigin.Begin);
        byte[] decrypted = new byte[newSize];
        int totalRead = 0;
        while (totalRead < newSize)
        {
            int n = stream.Read(decrypted, totalRead, newSize - totalRead);
            if (n == 0) break;
            totalRead += n;
        }

        Assert.Equal(plain[..newSize], decrypted);
        stream.Dispose();
    }

    [Fact]
    public void SetLength_ExpandsFile_ReadsAsZeros()
    {
        int originalSize = SectorSize * 2;
        byte[] plain = RandomNumberGenerator.GetBytes(originalSize);
        var (stream, baseStream, key) = CreateStream(originalSize);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        int newSize = SectorSize * 5;
        stream.SetLength(newSize);
        Assert.Equal(newSize, stream.Length);

        stream.Seek(0, SeekOrigin.Begin);
        byte[] decrypted = new byte[newSize];
        int totalRead = 0;
        while (totalRead < newSize)
        {
            int n = stream.Read(decrypted, totalRead, newSize - totalRead);
            if (n == 0) break;
            totalRead += n;
        }

        Assert.Equal(plain, decrypted[..originalSize]);
        Assert.Equal(new byte[newSize - originalSize], decrypted[originalSize..]);
        stream.Dispose();
    }

    [Fact]
    public void Read_PastEnd_ReturnsZero()
    {
        int size = SectorSize;
        byte[] plain = RandomNumberGenerator.GetBytes(size);
        var (stream, baseStream, key) = CreateStream(size);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        stream.Seek(0, SeekOrigin.Begin);
        byte[] decrypted = new byte[size];
        stream.Read(decrypted, 0, size);

        byte[] buf = new byte[10];
        int n = stream.Read(buf, 0, buf.Length);
        Assert.Equal(0, n);
        stream.Dispose();
    }

    [Fact]
    public void Read_SmallBuffer_MultipleCalls()
    {
        int size = SectorSize * 3;
        byte[] plain = RandomNumberGenerator.GetBytes(size);
        var (stream, baseStream, key) = CreateStream(size);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        stream.Seek(0, SeekOrigin.Begin);
        byte[] decrypted = new byte[size];
        int smallBufSize = 123;
        byte[] smallBuf = new byte[smallBufSize];
        int totalRead = 0;

        while (totalRead < size)
        {
            int toRead = Math.Min(smallBufSize, size - totalRead);
            int n = stream.Read(smallBuf, 0, toRead);
            if (n == 0) break;
            Array.Copy(smallBuf, 0, decrypted, totalRead, n);
            totalRead += n;
        }

        Assert.Equal(size, totalRead);
        Assert.Equal(plain, decrypted);
        stream.Dispose();
    }

    [Fact]
    public void Disposed_Read_Throws()
    {
        var (stream, baseStream, key) = CreateStream(SectorSize);
        stream.Dispose();

        byte[] buf = new byte[10];
        Assert.Throws<ObjectDisposedException>(() => stream.Read(buf, 0, buf.Length));
    }

    [Fact]
    public void Disposed_Write_Throws()
    {
        var (stream, baseStream, key) = CreateStream(SectorSize);
        stream.Dispose();

        byte[] buf = new byte[10];
        Assert.Throws<ObjectDisposedException>(() => stream.Write(buf, 0, buf.Length));
    }

    [Fact]
    public void Disposed_Seek_Throws()
    {
        var (stream, baseStream, key) = CreateStream(SectorSize);
        stream.Dispose();

        Assert.Throws<ObjectDisposedException>(() => stream.Seek(0, SeekOrigin.Begin));
    }

    [Fact]
    public void ReadOnly_Stream_WriteThrows()
    {
        var (stream, baseStream, key) = CreateStream(SectorSize, writable: false);
        byte[] buf = new byte[10];

        Assert.Throws<NotSupportedException>(() => stream.Write(buf, 0, buf.Length));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(100));
        stream.Dispose();
    }

    [Fact]
    public void DifferentSectorIndex_DifferentCiphertext()
    {
        byte[] plain = new byte[SectorSize];
        plain.AsSpan().Fill(0x42);

        var (stream, baseStream, key) = CreateStream(SectorSize * 2);

        stream.Seek(0, SeekOrigin.Begin);
        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        stream.Seek(SectorSize, SeekOrigin.Begin);
        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        byte[] baseData = baseStream.ToArray();
        byte[] sector0Cipher = baseData[..SectorSize];
        byte[] sector1Cipher = baseData[SectorSize..(SectorSize * 2)];

        Assert.NotEqual(sector0Cipher, sector1Cipher);
        stream.Dispose();
    }

    [Fact]
    public void Position_TracksCorrectly()
    {
        int size = SectorSize * 2;
        byte[] plain = RandomNumberGenerator.GetBytes(size);
        var (stream, baseStream, key) = CreateStream(size);

        stream.Write(plain, 0, plain.Length);
        Assert.Equal(size, stream.Position);

        stream.Seek(0, SeekOrigin.Begin);
        Assert.Equal(0, stream.Position);

        byte[] buf = new byte[SectorSize];
        stream.Read(buf, 0, SectorSize);
        Assert.Equal(SectorSize, stream.Position);

        stream.Dispose();
    }

    [Fact]
    public void EmptyFile_ReadsZeroBytes()
    {
        var (stream, baseStream, key) = CreateStream(0);

        byte[] buf = new byte[10];
        int n = stream.Read(buf, 0, buf.Length);

        Assert.Equal(0, n);
        Assert.Equal(0, stream.Length);
        stream.Dispose();
    }

    [Fact]
    public void LargeFile_MultipleChunks_Roundtrip()
    {
        int size = SectorSize * 100;
        byte[] plain = RandomNumberGenerator.GetBytes(size);
        var (stream, baseStream, key) = CreateStream(size);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        stream.Seek(0, SeekOrigin.Begin);
        byte[] decrypted = new byte[size];
        int totalRead = 0;
        while (totalRead < size)
        {
            int n = stream.Read(decrypted, totalRead, size - totalRead);
            if (n == 0) break;
            totalRead += n;
        }

        Assert.Equal(size, totalRead);
        Assert.Equal(plain, decrypted);
        stream.Dispose();
    }

    [Fact]
    public void WriteAtBeginning_ReadAtEnd_BothCorrect()
    {
        int size = SectorSize * 10;
        var (stream, baseStream, key) = CreateStream(size);

        // 先頭にデータを書き込み
        byte[] headData = RandomNumberGenerator.GetBytes(SectorSize);
        stream.Seek(0, SeekOrigin.Begin);
        stream.Write(headData, 0, headData.Length);
        stream.Flush();

        // 末尾にデータを書き込み
        byte[] tailData = RandomNumberGenerator.GetBytes(SectorSize);
        stream.Seek(size - SectorSize, SeekOrigin.Begin);
        stream.Write(tailData, 0, tailData.Length);
        stream.Flush();

        // 先頭データを確認
        stream.Seek(0, SeekOrigin.Begin);
        byte[] readHead = new byte[SectorSize];
        stream.Read(readHead, 0, SectorSize);
        Assert.Equal(headData, readHead);

        // 末尾データを確認
        stream.Seek(size - SectorSize, SeekOrigin.Begin);
        byte[] readTail = new byte[SectorSize];
        stream.Read(readTail, 0, SectorSize);
        Assert.Equal(tailData, readTail);

        stream.Dispose();
    }

    [Fact]
    public void MultipleRandomWritesAndReads_ConsistencyCheck()
    {
        int size = SectorSize * 20;
        var (stream, baseStream, key) = CreateStream(size);

        var random = new Random(42);
        var expectedData = new byte[size];
        expectedData.AsSpan().Fill(0xFF);

        // 初期データとして0xFFを書き込む
        stream.Seek(0, SeekOrigin.Begin);
        stream.Write(expectedData, 0, expectedData.Length);
        stream.Flush();

        // ランダムな位置にランダムなデータを書き込み
        for (int i = 0; i < 50; i++)
        {
            int offset = random.Next(0, size - 100);
            int writeSize = random.Next(10, 200);
            byte[] writeData = new byte[writeSize];
            random.NextBytes(writeData);

            stream.Seek(offset, SeekOrigin.Begin);
            stream.Write(writeData, 0, writeSize);
            stream.Flush();

            Array.Copy(writeData, 0, expectedData, offset, writeSize);
        }

        // 全体を読み取り
        stream.Seek(0, SeekOrigin.Begin);
        byte[] actualData = new byte[size];
        int totalRead = 0;
        while (totalRead < size)
        {
            int n = stream.Read(actualData, totalRead, size - totalRead);
            if (n == 0) break;
            totalRead += n;
        }

        Assert.Equal(expectedData, actualData);
        stream.Dispose();
    }
}
