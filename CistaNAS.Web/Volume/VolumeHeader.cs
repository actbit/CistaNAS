using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CistaNAS.Web.Crypto;
using CistaNAS.Web.Models;

namespace CistaNAS.Web.Volume;

/// <summary>
/// ボリュームヘッダ（volume.json）。低レベルな Volume 層の実装。
/// マスター鍵をユーザーごとに AES-256-GCM ラップして保存。
/// 共有ボリュームでは複数ユーザーのエントリが存在する。
/// </summary>
public sealed class VolumeHeader
{
    public const string FileName = "volume.json";
    private const int GcmTagSize = 16;
    private const int GcmNonceSize = 12;
    private const int KekSize = 32;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public string Name { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public bool Encrypted { get; set; } = true;
    public int SectorSize { get; set; }

    /// <summary>"server" (サーバー側 AES-XTS) or "e2ee" (クライアント側暗号化)。</summary>
    public string EncryptionMode { get; set; } = "server";

    /// <summary>E2EE チャンクサイズ（バイト）。EncryptionMode が "e2ee" の場合のみ使用。</summary>
    public int ChunkSize { get; set; } = 1048576;

    /// <summary>ボリュームの作成者（削除不可）。</summary>
    public string OwnerUser { get; set; } = "";

    /// <summary>ユーザーごとのラップ済み鍵。キー = ユーザー名。</summary>
    public Dictionary<string, UserWrappedKey> UserKeys { get; set; } = new(StringComparer.Ordinal);

    /// <summary>アクセスを許可されたグループ名（サーバー暗号化ボリュームのみ）。</summary>
    public HashSet<string> AuthorizedGroups { get; set; } = new(StringComparer.Ordinal);

    public sealed class UserWrappedKey
    {
        public KdfParams Kdf { get; set; } = new();
        public WrappedKey WrappedMasterKey { get; set; } = new();
    }

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
    /// E2EE ボリュームを作成。マスターキーはクライアントで生成・ラップ済み。
    /// </summary>
    public static VolumeHeader CreateE2ee(
        string name, string username, UserWrappedKey wrappedKey, int chunkSize)
    {
        return new VolumeHeader
        {
            Name = name,
            CreatedAt = DateTimeOffset.UtcNow,
            Encrypted = true,
            EncryptionMode = "e2ee",
            ChunkSize = chunkSize,
            SectorSize = 0,
            OwnerUser = username,
            UserKeys = { [username] = wrappedKey },
        };
    }

    /// <summary>E2EE ボリュームにユーザーの wrapped key を追加（クライアント側で再ラップ済み）。</summary>
    public void AddWrappedKey(string username, UserWrappedKey wrappedKey)
    {
        UserKeys[username] = wrappedKey;
    }

    public bool IsE2ee => EncryptionMode == "e2ee";

    /// <summary>
    /// KEK 導出: PBKDF2-SHA256(password, SHA256(username) || salt, iterations, 32)
    /// ユーザー名がソルトの一部 → 同じパスワードでもユーザー違いで別 KEK。
    /// </summary>
    private static byte[] DeriveKek(string username, string password, byte[] salt, int iterations)
    {
        byte[] userHash = SHA256.HashData(Encoding.UTF8.GetBytes(username));
        byte[] combinedSalt = new byte[userHash.Length + salt.Length];
        Buffer.BlockCopy(userHash, 0, combinedSalt, 0, userHash.Length);
        Buffer.BlockCopy(salt, 0, combinedSalt, userHash.Length, salt.Length);
        return Rfc2898DeriveBytes.Pbkdf2(password, combinedSalt, iterations, HashAlgorithmName.SHA256, KekSize);
    }

    private static (byte[] Nonce, byte[] Ciphertext, byte[] Tag) WrapKey(byte[] masterKey, byte[] kek)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(GcmNonceSize);
        byte[] ct = new byte[masterKey.Length];
        byte[] tag = new byte[GcmTagSize];
        using (var gcm = new AesGcm(kek, GcmTagSize))
            gcm.Encrypt(nonce, masterKey, ct, tag);
        return (nonce, ct, tag);
    }

    private static byte[] UnwrapKey(WrappedKey wk, byte[] kek)
    {
        byte[] master = new byte[wk.Ciphertext.Length];
        using var gcm = new AesGcm(kek, GcmTagSize);
        gcm.Decrypt(wk.Nonce, wk.Ciphertext, wk.Tag, master);
        return master;
    }

    // ---- 公開 API ----

    /// <summary>新しいボリュームの header＋マスター鍵を生成する。</summary>
    public static (VolumeHeader Header, byte[]? MasterKey) Create(
        string name, string? username, string? password, int sectorSize, int kdfIterations, bool encrypted = true)
    {
        if (!encrypted)
        {
            return (new VolumeHeader
            {
                Name = name,
                CreatedAt = DateTimeOffset.UtcNow,
                Encrypted = false,
                SectorSize = sectorSize,
                OwnerUser = username ?? "",
            }, null);
        }

        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentException.ThrowIfNullOrEmpty(password);

        byte[] master = KeyDerivation.NewMasterKey();
        var header = new VolumeHeader
        {
            Name = name,
            CreatedAt = DateTimeOffset.UtcNow,
            Encrypted = true,
            SectorSize = sectorSize,
            OwnerUser = username,
        };
        header.AddUserWrap(username, password, master, kdfIterations);
        return (header, master);
    }

    /// <summary>追加ユーザーのためにマスター鍵をラップして登録。</summary>
    public void AddUserWrap(string username, string password, byte[] masterKey, int kdfIterations)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentException.ThrowIfNullOrEmpty(password);

        byte[] salt = KeyDerivation.NewSalt();
        byte[] kek = DeriveKek(username, password, salt, kdfIterations);
        try
        {
            var (nonce, ct, tag) = WrapKey(masterKey, kek);
            UserKeys[username] = new UserWrappedKey
            {
                Kdf = new KdfParams { Iterations = kdfIterations, Salt = salt },
                WrappedMasterKey = new WrappedKey { Nonce = nonce, Ciphertext = ct, Tag = tag },
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>指定ユーザーのエントリを新しいパスワードで再ラップ。</summary>
    public void RewrapUser(string username, string oldPassword, string newPassword, int kdfIterations)
    {
        if (!UserKeys.TryGetValue(username, out var entry))
            throw new VolumeException($"ユーザー '{username}' はこのボリュームにアクセス権がありません。");

        byte[] oldKek = DeriveKek(username, oldPassword, entry.Kdf.Salt, entry.Kdf.Iterations);
        try
        {
            byte[] masterKey = UnwrapKey(entry.WrappedMasterKey, oldKek);
            try
            {
                // 新しいソルトで再ラップ
                byte[] newSalt = KeyDerivation.NewSalt();
                byte[] newKek = DeriveKek(username, newPassword, newSalt, kdfIterations);
                try
                {
                    var (nonce, ct, tag) = WrapKey(masterKey, newKek);
                    UserKeys[username] = new UserWrappedKey
                    {
                        Kdf = new KdfParams { Iterations = kdfIterations, Salt = newSalt },
                        WrappedMasterKey = new WrappedKey { Nonce = nonce, Ciphertext = ct, Tag = tag },
                    };
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(newKek);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(masterKey);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(oldKek);
        }
    }

    /// <summary>ユーザーのアクセス権を削除。オーナーは削除不可。</summary>
    public bool RemoveUserWrap(string username)
    {
        if (username == OwnerUser)
            throw new VolumeException("オーナーは削除できません。");
        return UserKeys.Remove(username);
    }

    /// <summary>ユーザーがアクセス権を持つか。</summary>
    public bool HasUserAccess(string username) => UserKeys.ContainsKey(username);

    /// <summary>指定ユーザーでマスター鍵をアンラップ。失敗時 null。</summary>
    public byte[]? UnwrapMasterKey(string username, string password)
    {
        if (!Encrypted) return null;
        if (!UserKeys.TryGetValue(username, out var entry)) return null;

        byte[] kek = DeriveKek(username, password, entry.Kdf.Salt, entry.Kdf.Iterations);
        try
        {
            return UnwrapKey(entry.WrappedMasterKey, kek);
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
