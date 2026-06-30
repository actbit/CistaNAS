using CistaNAS.Client.Security;

namespace CistaNAS.Tests;

/// <summary>
/// SecureBuffer のテスト: VirtualLock（ページング退避防止）と Dispose でのゼロクリアを検証。
/// </summary>
public class SecureBufferTests
{
    /// <summary>Dispose 後、元の byte[] がゼロクリアされること。</summary>
    [Fact]
    public void Dispose_ZeroFillsBuffer()
    {
        var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var buf = new SecureBuffer(data);

        Assert.Equal(8, buf.Length);
        buf.Dispose();

        // 元の配列がゼロクリアされていること（ピン固定しているため同じ参照）
        Assert.True(data.AsSpan().SequenceEqual(new byte[8]));
    }

    /// <summary>Buffer は元の byte[] と同じ参照を返すこと（E2eeCrypto に渡す用）。</summary>
    [Fact]
    public void Buffer_ReturnsOriginalArray()
    {
        var data = new byte[] { 0xAA, 0xBB, 0xCC };
        using var buf = new SecureBuffer(data);

        Assert.Same(data, buf.Buffer);
    }

    /// <summary>Dispose は冪等（複数回呼び出しで例外なし）。</summary>
    [Fact]
    public void Dispose_IsIdempotent()
    {
        var buf = new SecureBuffer(new byte[16]);
        buf.Dispose();
        buf.Dispose(); // 2回目は例外なし
    }

    /// <summary>Dispose 後の Buffer アクセスは ObjectDisposedException。</summary>
    [Fact]
    public void Buffer_AfterDispose_Throws()
    {
        var buf = new SecureBuffer(new byte[4]);
        buf.Dispose();

        Assert.Throws<ObjectDisposedException>(() => buf.Buffer);
    }

    /// <summary>長いライフサイクル（マスターキー相当 32 bytes）でも VirtualLock + Dispose が成功。</summary>
    [Fact]
    public void MasterKeySize_LockAndUnlockSucceeds()
    {
        var masterKey = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(masterKey);
        var buf = new SecureBuffer(masterKey);

        // ロック中はアクセス可能
        Assert.Equal(32, buf.Span.Length);
        buf.Dispose();

        // ゼロクリア
        Assert.True(masterKey.AsSpan().SequenceEqual(new byte[32]));
    }
}
