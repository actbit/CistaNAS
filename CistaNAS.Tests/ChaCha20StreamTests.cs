using System.Security.Cryptography;
using CistaNAS.Client.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// ChaCha20Stream の単体テスト。
/// 純粋な ChaCha20 カウンタモードストリーム（XTS なし）の動作を検証。
/// </summary>
public class ChaCha20StreamTests
{
    private const int SectorSize = 16; // テスト用に小さめ

    /// <summary>
    /// テスト用 ChaCha20Stream を作成。
    /// </summary>
    private static (ChaCha20Stream stream, MemoryStream baseStream, byte[] key, byte[] nonce) CreateStream(long length, bool writable = true)
    {
        var baseStream = new MemoryStream();
        // 基礎ストリームを十分に確保
        baseStream.SetLength(length + SectorSize);

        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);

        var stream = new ChaCha20Stream(baseStream, key, nonce, length, writable);
        return (stream, baseStream, key, nonce);
    }

    [Fact]
    public void Read_SingleSector_Roundtrip()
    {
        byte[] plain = RandomNumberGenerator.GetBytes(SectorSize);
        var (stream, baseStream, key, nonce) = CreateStream(SectorSize);

        // 書き込み（暗号化）
        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        // 読み取り（復号化）
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
        var (stream, baseStream, key, nonce) = CreateStream(size);

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
        // セクタサイズ未満のデータ
        int size = SectorSize - 5;
        byte[] plain = RandomNumberGenerator.GetBytes(size);
        var (stream, baseStream, key, nonce) = CreateStream(SectorSize);

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
        var (stream, baseStream, key, nonce) = CreateStream(size);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        // セクタ2の先頭にシーク
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
        var (stream, baseStream, key, nonce) = CreateStream(size);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        // 先頭から開始
        stream.Seek(0, SeekOrigin.Begin);
        Assert.Equal(0, stream.Position);

        // 現在位置から相移動
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
        var (stream, baseStream, key, nonce) = CreateStream(size);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        // 末尾から SectorSize 戻る
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
        var (stream, baseStream, key, nonce) = CreateStream(size);

        // 全体を書き込み
        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        // セクタ1の中央を更新
        int updateOffset = SectorSize + 5;
        int updateSize = 8;
        byte[] updateData = RandomNumberGenerator.GetBytes(updateSize);

        stream.Seek(updateOffset, SeekOrigin.Begin);
        stream.Write(updateData, 0, updateSize);
        stream.Flush();

        // 更新部分を読み取り
        stream.Seek(updateOffset, SeekOrigin.Begin);
        byte[] readBack = new byte[updateSize];
        stream.Read(readBack, 0, readBack.Length);

        Assert.Equal(updateData, readBack);

        // 前後のデータが変わっていないことを確認
        stream.Seek(0, SeekOrigin.Begin);
        byte[] decrypted = new byte[size];
        int totalRead = 0;
        while (totalRead < size)
        {
            int n = stream.Read(decrypted, totalRead, size - totalRead);
            if (n == 0) break;
            totalRead += n;
        }

        // 更新前の元データと比較
        Assert.Equal(plain[..updateOffset], decrypted[..updateOffset]);
        Assert.Equal(updateData, decrypted[updateOffset..(updateOffset + updateSize)]);
        Assert.Equal(plain[(updateOffset + updateSize)..], decrypted[(updateOffset + updateSize)..]);
        stream.Dispose();
    }

    [Fact]
    public void Write_CrossSectorBoundary_WorksCorrectly()
    {
        int size = SectorSize * 3;
        byte[] plain = RandomNumberGenerator.GetBytes(size);
        var (stream, baseStream, key, nonce) = CreateStream(size);

        // セクタ境界をまたぐ書き込み
        int writeOffset = SectorSize - 5;
        int writeSize = SectorSize + 10; // セクタ1の末尾5B + セクタ2全体 + セクタ3の先頭5B
        byte[] writeData = RandomNumberGenerator.GetBytes(writeSize);

        stream.Seek(writeOffset, SeekOrigin.Begin);
        stream.Write(writeData, 0, writeSize);
        stream.Flush();

        // 書き戻しを確認
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
        var (stream, baseStream, key, nonce) = CreateStream(originalSize);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        // サイズを縮小
        int newSize = SectorSize * 2;
        stream.SetLength(newSize);
        Assert.Equal(newSize, stream.Length);

        // 新しいサイズで読み取り
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
        var (stream, baseStream, key, nonce) = CreateStream(originalSize);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        // サイズを拡張
        int newSize = SectorSize * 5;
        stream.SetLength(newSize);
        Assert.Equal(newSize, stream.Length);

        // 拡張部分を読み取り（ゼロであるべき）
        stream.Seek(0, SeekOrigin.Begin);
        byte[] decrypted = new byte[newSize];
        int totalRead = 0;
        while (totalRead < newSize)
        {
            int n = stream.Read(decrypted, totalRead, newSize - totalRead);
            if (n == 0) break;
            totalRead += n;
        }

        // 元データ部分
        Assert.Equal(plain, decrypted[..originalSize]);

        // 拡張部分はゼロ
        Assert.Equal(new byte[newSize - originalSize], decrypted[originalSize..]);
        stream.Dispose();
    }

    [Fact]
    public void Read_PastEnd_ReturnsZero()
    {
        int size = SectorSize;
        byte[] plain = RandomNumberGenerator.GetBytes(size);
        var (stream, baseStream, key, nonce) = CreateStream(size);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        // 末尾まで読み取り
        stream.Seek(0, SeekOrigin.Begin);
        byte[] decrypted = new byte[size];
        stream.Read(decrypted, 0, size);

        // 末尾以降は 0 を返す
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
        var (stream, baseStream, key, nonce) = CreateStream(size);

        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        // 小バッファで複数回読み取り
        stream.Seek(0, SeekOrigin.Begin);
        byte[] decrypted = new byte[size];
        int smallBufSize = 7; // セクタサイズで割り切れない
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
        var (stream, baseStream, key, nonce) = CreateStream(SectorSize);
        stream.Dispose();

        byte[] buf = new byte[10];
        Assert.Throws<ObjectDisposedException>(() => stream.Read(buf, 0, buf.Length));
    }

    [Fact]
    public void Disposed_Write_Throws()
    {
        var (stream, baseStream, key, nonce) = CreateStream(SectorSize);
        stream.Dispose();

        byte[] buf = new byte[10];
        Assert.Throws<ObjectDisposedException>(() => stream.Write(buf, 0, buf.Length));
    }

    [Fact]
    public void Disposed_Seek_Throws()
    {
        var (stream, baseStream, key, nonce) = CreateStream(SectorSize);
        stream.Dispose();

        Assert.Throws<ObjectDisposedException>(() => stream.Seek(0, SeekOrigin.Begin));
    }

    [Fact]
    public void ReadOnly_Stream_WriteThrows()
    {
        var (stream, baseStream, key, nonce) = CreateStream(SectorSize, writable: false);
        byte[] buf = new byte[10];

        Assert.Throws<InvalidOperationException>(() => stream.Write(buf, 0, buf.Length));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(100));
        stream.Dispose();
    }

    [Fact]
    public void DifferentSectorIndex_DifferentCiphertext()
    {
        byte[] plain = new byte[SectorSize];
        plain.AsSpan().Fill(0x42); // 同じデータ

        var (stream, baseStream, key, nonce) = CreateStream(SectorSize * 2);

        // セクタ0に書き込み
        stream.Seek(0, SeekOrigin.Begin);
        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        // セクタ1に書き込み
        stream.Seek(SectorSize, SeekOrigin.Begin);
        stream.Write(plain, 0, plain.Length);
        stream.Flush();

        // 基礎ストリーム上で異なる暗号文になっている
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
        var (stream, baseStream, key, nonce) = CreateStream(size);

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
        var (stream, baseStream, key, nonce) = CreateStream(0);

        byte[] buf = new byte[10];
        int n = stream.Read(buf, 0, buf.Length);

        Assert.Equal(0, n);
        Assert.Equal(0, stream.Length);
        stream.Dispose();
    }

    [Fact]
    public void LargeFile_MultipleChunks_Roundtrip()
    {
        int size = SectorSize * 1000;
        byte[] plain = RandomNumberGenerator.GetBytes(size);
        var (stream, baseStream, key, nonce) = CreateStream(size);

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
}
