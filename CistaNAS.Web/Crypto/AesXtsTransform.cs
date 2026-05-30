using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CistaNAS.Web.Crypto;

/// <summary>
/// AES-XTS の低レベル変換クラス。
/// ストリーム不要のバッファ単位暗号化/復号に使用（チャンクストレージ等）。
/// IEEE 1619 / NIST SP 800-38E 準拠。
/// </summary>
public sealed class AesXtsTransform : IDisposable
{
    private const int BlockSize = 16;

    private readonly ICryptoTransform _dataEnc;
    private readonly ICryptoTransform _dataDec;
    private readonly ICryptoTransform _tweakEnc;
    private readonly Aes _dataAes;
    private readonly Aes _tweakAes;

    /// <param name="key">K1||K2 の 64 バイト。</param>
    /// <param name="sectorSize">セクタサイズ（16 の倍数）。</param>
    public AesXtsTransform(ReadOnlySpan<byte> key, int sectorSize)
    {
        if (key.Length != KeyDerivation.MasterKeySize)
            throw new ArgumentException("AES-256-XTS の鍵は 64 バイト（K1||K2）。", nameof(key));
        if (sectorSize <= 0 || sectorSize % BlockSize != 0)
            throw new ArgumentException("セクタサイズは 16 の倍数であること。", nameof(sectorSize));

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
        byte[] inBuf = du.ToArray();
        byte[] outBuf = new byte[BlockSize];
        _tweakEnc.TransformBlock(inBuf, 0, BlockSize, outBuf, 0);
        outBuf.CopyTo(tweak);
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
        _dataEnc.Dispose();
        _dataDec.Dispose();
        _tweakEnc.Dispose();
        CryptographicOperations.ZeroMemory(_dataAes.Key);
        CryptographicOperations.ZeroMemory(_tweakAes.Key);
        _dataAes.Dispose();
        _tweakAes.Dispose();
    }
}
