using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CistaNAS.Web.Crypto;

namespace CistaNAS.Web.Volume;

/// <summary>
/// ボリュームヘッダ（volume.json）。低レベルな Volume 層の実装。
/// マスター鍵は「ユーザー名＋パスワード」のハッシュ由来 KEK で AES-256-GCM ラップする。
/// 誤認証情報は GCM 認証失敗で検出。
/// </summary>
public sealed class VolumeHeader
{
    public const string FileName = "volume.json";
    private const int CurrentFormatVersion = 2;
    private const int GcmTagSize = 16;
    private const int GcmNonceSize = 12;
    private const int KekSize = 32;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public int FormatVersion { get; set; } = CurrentFormatVersion;
    public string Name { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public bool Encrypted { get; set; } = true;
    public int SectorSize { get; set; }

    /// <summary>ボリュームを所有するユーザー。KEK 導出に使うユーザー名を記録。</summary>
    public string OwnerUser { get; set; } = "";

    public KdfParams Kdf { get; set; } = new();
    public WrappedKey WrappedMasterKey { get; set; } = new();

    public sealed class KdfParams
    {
        public string Algorithm { get; set; } = "pbkdf2-sha256";
        public int Iterations { get; set; }
        public byte[] Salt { get; set; } = [];
    }

    public sealed class WrappedKey
    {
        public string Algorithm { get; set; } = "aes-256-gcm";
        public byte[] Nonce { get; set; } = [];
        public byte[] Ciphertext { get; set; } = [];
        public byte[] Tag { get; set; } = [];
    }

    /// <summary>
    /// ユーザー名＋パスワードから KEK を導出する。
    /// KEK = PBKDF2-SHA256(password, SHA256(username) || salt, iterations, 32)
    /// ユーザー名がソルトの一部になることで、同じパスワードでもユーザーが違えば別の KEK になる。
    /// </summary>
    private static byte[] DeriveKek(string username, string password, byte[] salt, int iterations)
    {
        // ユーザー名をハッシュしてソルトの前に結合
        byte[] userHash = SHA256.HashData(Encoding.UTF8.GetBytes(username));
        byte[] combinedSalt = new byte[userHash.Length + salt.Length];
        Buffer.BlockCopy(userHash, 0, combinedSalt, 0, userHash.Length);
        Buffer.BlockCopy(salt, 0, combinedSalt, userHash.Length, salt.Length);

        return Rfc2898DeriveBytes.Pbkdf2(password, combinedSalt, iterations, HashAlgorithmName.SHA256, KekSize);
    }

    /// <summary>新しいボリュームの header＋マスター鍵を生成する。</summary>
    public static (VolumeHeader Header, byte[]? MasterKey) Create(
        string name, string? username, string? password, int sectorSize, int kdfIterations, bool encrypted = true)
    {
        if (!encrypted)
        {
            var plainHeader = new VolumeHeader
            {
                Name = name,
                CreatedAt = DateTimeOffset.UtcNow,
                Encrypted = false,
                SectorSize = sectorSize,
                OwnerUser = username ?? "",
            };
            return (plainHeader, null);
        }

        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentException.ThrowIfNullOrEmpty(password);

        byte[] master = KeyDerivation.NewMasterKey();
        byte[] salt = KeyDerivation.NewSalt();
        byte[] kek = DeriveKek(username, password, salt, kdfIterations);

        byte[] nonce = RandomNumberGenerator.GetBytes(GcmNonceSize);
        byte[] ct = new byte[master.Length];
        byte[] tag = new byte[GcmTagSize];
        using (var gcm = new AesGcm(kek, GcmTagSize))
            gcm.Encrypt(nonce, master, ct, tag);
        CryptographicOperations.ZeroMemory(kek);

        var header = new VolumeHeader
        {
            Name = name,
            CreatedAt = DateTimeOffset.UtcNow,
            Encrypted = true,
            SectorSize = sectorSize,
            OwnerUser = username,
            Kdf = new KdfParams { Iterations = kdfIterations, Salt = salt },
            WrappedMasterKey = new WrappedKey { Nonce = nonce, Ciphertext = ct, Tag = tag },
        };
        return (header, master);
    }

    /// <summary>
    /// ユーザー名＋パスワードからマスター鍵を復元する。
    /// 未暗号化ボリュームなら null。誤認証情報でも null。
    /// </summary>
    public byte[]? UnwrapMasterKey(string username, string password)
    {
        if (!Encrypted) return null;

        byte[] kek = DeriveKek(username, password, Kdf.Salt, Kdf.Iterations);
        try
        {
            byte[] master = new byte[WrappedMasterKey.Ciphertext.Length];
            using var gcm = new AesGcm(kek, GcmTagSize);
            gcm.Decrypt(WrappedMasterKey.Nonce, WrappedMasterKey.Ciphertext, WrappedMasterKey.Tag, master);
            return master;
        }
        catch (AuthenticationTagMismatchException)
        {
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    public void Save(string path)
    {
        string tmp = path + ".tmp";
        using (var fs = File.Create(tmp))
            JsonSerializer.Serialize(fs, this, JsonOptions);
        File.Move(tmp, path, overwrite: true);
    }

    public static VolumeHeader Load(string path)
    {
        using var fs = File.OpenRead(path);
        return JsonSerializer.Deserialize<VolumeHeader>(fs, JsonOptions)
            ?? throw new InvalidDataException("ボリュームヘッダを読み込めません。");
    }
}
