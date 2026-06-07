using System.Buffers;
using System.Buffers.Binary;

namespace CistaNAS.Shared.Crypto;

/// <summary>
/// AES-XTS の低レベル変換クラス。
/// ストリーム不要のバッファ単位暗号化/復号に使用（チャンクストレージ等）。
/// IEEE 1619 / NIST SP 800-38E 準拠。
/// </summary>
public sealed class AesXtsTransform : IDisposable
{
    private const int BlockSize = 16;

    private readonly IAesEcb _dataEnc;
    private readonly IAesEcb _dataDec;
    private readonly IAesEcb _tweakEnc;
    private bool _disposed;

    /// <param name="key">K1||K2 の 64 バイト。</param>
    /// <param name="sectorSize">セクタサイズ（16 の倍数）。</param>
    public AesXtsTransform(ReadOnlySpan<byte> key, int sectorSize)
    {
        if (key.Length != KeyDerivation.MasterKeySize)
            throw new ArgumentException("AES-256-XTS の鍵は 64 バイト（K1||K2）。", nameof(key));
        if (sectorSize <= 0 || sectorSize % BlockSize != 0)
            throw new ArgumentException("セクタサイズは 16 の倍数であること。", nameof(sectorSize));

        // WASM / ネイティブ自動切替
        _dataEnc = AesEcbFactory.CreateEncryptor(key[..32]);
        _dataDec = AesEcbFactory.CreateFull(key[..32]);  // 復号にも使用
        _tweakEnc = AesEcbFactory.CreateEncryptor(key[32..]);
    }

    /// <summary>GF(2^128) での α 倍（多項式 x^128+x^7+x^2+x+1, リトルエンディアン）。</summary>
    internal static void MultiplyAlpha(Span<byte> t)
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
        Span<byte> du = stackalloc byte[BlockSize];
        du.Clear();
        BinaryPrimitives.WriteUInt64LittleEndian(du, (ulong)sectorIndex);
        _tweakEnc.EncryptBlock(du, tweak);
    }

    /// <summary>
    /// データを AES-XTS で in-place 暗号化/復号する。
    /// データ長は 16 の倍数であること（セクタ境界）。
    /// </summary>
    /// <param name="firstSectorIndex">最初のセクタインデックス。</param>
    /// <param name="data">暗号化/復号するデータ（16 の倍数長）。</param>
    /// <param name="encrypt">true = 暗号化, false = 復号。</param>
    public void Transform(long firstSectorIndex, Span<byte> data, bool encrypt)
    {
        if (data.Length % BlockSize != 0)
            throw new ArgumentException("データ長は 16 の倍数であること。", nameof(data));

        Span<byte> t = stackalloc byte[BlockSize];
        ComputeTweak(firstSectorIndex, t);

        Span<byte> tmpIn = stackalloc byte[BlockSize];
        Span<byte> tmpOut = stackalloc byte[BlockSize];

        for (int off = 0; off < data.Length; off += BlockSize)
        {
            Span<byte> blk = data.Slice(off, BlockSize);
            for (int i = 0; i < BlockSize; i++) tmpIn[i] = (byte)(blk[i] ^ t[i]);
            if (encrypt)
                _dataEnc.EncryptBlock(tmpIn, tmpOut);
            else
                _dataDec.DecryptBlock(tmpIn, tmpOut);
            for (int i = 0; i < BlockSize; i++) blk[i] = (byte)(tmpOut[i] ^ t[i]);
            MultiplyAlpha(t);
        }
    }

    /// <summary>
    /// データを AES-XTS で暗号化する。出力バッファに出力。
    /// </summary>
    public void Encrypt(long firstSectorIndex, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
    {
        plaintext.CopyTo(ciphertext);
        Transform(firstSectorIndex, ciphertext, encrypt: true);
    }

    /// <summary>
    /// データを AES-XTS で復号する。出力バッファに出力。
    /// </summary>
    public void Decrypt(long firstSectorIndex, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        ciphertext.CopyTo(plaintext);
        Transform(firstSectorIndex, plaintext, encrypt: false);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _dataEnc.Dispose();
        _dataDec.Dispose();
        _tweakEnc.Dispose();
    }
}
