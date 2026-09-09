using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CistaNAS.Shared.Crypto;
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

    /// <summary>ホームボリューム名のプレフィックス。例: "home__alice"。</summary>
    public const string HomePrefix = "home__";
    /// <summary>グループボリューム名のプレフィックス。例: "group__engineering"。</summary>
    public const string GroupPrefix = "group__";

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public string Name { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public bool Encrypted { get; set; } = true;
    public int SectorSize { get; set; }

    /// <summary>"server" (サーバー側 AES-XTS) or "e2ee" (クライアント側暗号化)。</summary>
    public string EncryptionMode { get; set; } = "server";

    /// <summary>暗号化アルゴリズム ("aes-256-xts", "aes-256-gcm", "chacha20-poly1305")</summary>
    public string CipherAlgorithm { get; set; } = "aes-256-xts";

    /// <summary>鍵長（ビット）</summary>
    public int KeySize { get; set; } = 256;

    /// <summary>ストレージモード。"local" (volume.dat) or "chunk" (S3/R2 チャンク分割)。</summary>
    public string StorageMode { get; set; } = "local";

    /// <summary>チャンクモード時のサーバー側チャンクサイズ（バイト）。EncryptionMode=="server" かつ StorageMode=="chunk" の場合に使用。</summary>
    public int ServerChunkSize { get; set; } = 4194304; // 4 MiB

    /// <summary>E2EE チャンクサイズ（バイト）。EncryptionMode が "e2ee" の場合のみ使用。</summary>
    public int ChunkSize { get; set; } = 1048576;

    /// <summary>ボリュームの作成者（削除不可）。</summary>
    public string OwnerUser { get; set; } = "";

    /// <summary>
    /// ボリュームの stable identifier（GUID "N" 形式）。crypto format v2 の AAD に bind する。
    /// ボリューム名リネーム後も不変。新規 E2EE ボリューム作成時に生成し、
    /// 既存ボリュームは共有昇格（epoch 1 生成）時に生成する。
    /// </summary>
    public string? VolumeId { get; set; }

    /// <summary>
    /// 共有 E2EE の GroupKey epoch。0 = v1（共有なしの単独 E2EE、masterKey 直使用）、
    /// ≥ 1 = 共有 v2 モード（GroupKey + per-file DEK）。
    /// </summary>
    public int KeyEpoch { get; set; }

    /// <summary>
    /// epoch ごとの GroupKey（remaining members の公開鍵で ECDH ラップ済み）。
    /// 旧 epoch は既存ファイル（その epoch の GroupKey でラップされた WrappedFileKey）を
    /// remaining members が引き続き読めるよう、revoke されていない限り保持する。
    /// </summary>
    public List<GroupEpochEntry> GroupKeyEpochs { get; set; } = [];

    /// <summary>epoch 単位の GroupKey wraps。</summary>
    public sealed class GroupEpochEntry
    {
        public int Epoch { get; set; }

        /// <summary>キー = ユーザー名。値 = そのユーザーの公開鍵でラップされた GroupKey。</summary>
        public Dictionary<string, UserWrappedKey> Wraps { get; set; } = new(StringComparer.Ordinal);

        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    }

    /// <summary>ユーザーごとのラップ済み鍵。キー = ユーザー名。</summary>
    public Dictionary<string, UserWrappedKey> UserKeys { get; set; } = new(StringComparer.Ordinal);

    /// <summary>アクセスを許可されたグループ名（サーバー暗号化ボリュームのみ）。</summary>
    public HashSet<string> AuthorizedGroups { get; set; } = new(StringComparer.Ordinal);

    /// <summary>ユーザーごとのクオータ（バイト）。0 = 無制限。キー = ユーザー名。</summary>
    public Dictionary<string, long> UserQuotas { get; set; } = new(StringComparer.Ordinal);

    public sealed class UserWrappedKey
    {
        public string WrapType { get; set; } = "password"; // "password" or "ecdh"
        public KdfParams Kdf { get; set; } = new();
        public WrappedKey WrappedMasterKey { get; set; } = new();
        public byte[]? EphemeralPublicKey { get; set; } // ECDH only: raw 65B uncompressed point

        /// <summary>
        /// 将来拡張用のメタデータ（KeyId / DeviceId / Signature 等）。
        /// Identity key 署名モデル導入時に使用。現行プロトコルでは未使用。
        /// </summary>
        public Dictionary<string, string>? Extensions { get; set; }
    }

    public sealed class KdfParams
    {
        /// <summary>"argon2id"（Argon2id+PBKDF2 合成、現行）or "argon2id-raw"（Argon2id 単独）or "pbkdf2-sha256"（レガシー単段）。</summary>
        public string Algorithm { get; set; } = KdfSpec.Pbkdf2Sha256;
        /// <summary>argon2id: 後段 PBKDF2 の反復数。argon2id-raw: 不使用（0）。pbkdf2-sha256: PBKDF2 反復数。</summary>
        public int Iterations { get; set; }
        /// <summary>argon2id 前段のメモリ量（KiB）。レガシー pbkdf2 では 0。</summary>
        public int MemoryKiB { get; set; }
        /// <summary>argon2id 前段のパス数（t）。レガシー pbkdf2 では 0。</summary>
        public int TimeCost { get; set; }
        /// <summary>argon2id 前段の並列度。レガシー pbkdf2 では 0。</summary>
        public int Parallelism { get; set; }
        public byte[] Salt { get; set; } = [];

        /// <summary>KdfSpec に変換（導出に渡す用）。</summary>
        public KdfSpec ToKdfSpec() => new(Algorithm, Iterations, MemoryKiB, Parallelism, TimeCost);

        /// <summary>現行既定（Argon2id 合成）の KdfParams を生成する。</summary>
        public static KdfParams FromSpec(KdfSpec spec, byte[] salt) => new()
        {
            Algorithm = spec.Algorithm,
            Iterations = spec.Iterations,
            MemoryKiB = spec.MemoryKiB,
            TimeCost = spec.TimeCost,
            Parallelism = spec.Parallelism,
            Salt = salt,
        };
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
            StorageMode = "chunk", // E2EEはチャンクモード必須
            ChunkSize = chunkSize,
            SectorSize = 0,
            OwnerUser = username,
            VolumeId = Guid.NewGuid().ToString("N"),
            UserKeys = { [username] = wrappedKey },
        };
    }

    /// <summary>E2EE ボリュームにユーザーの wrapped key を追加（クライアント側で再ラップ済み）。</summary>
    public void AddWrappedKey(string username, UserWrappedKey wrappedKey)
    {
        UserKeys[username] = wrappedKey;
    }

    // ---- 共有 v2（GroupKey epoch） ----

    /// <summary>VolumeId を取得。未生成なら新規生成してヘッダに設定する。</summary>
    public string EnsureVolumeId()
    {
        if (string.IsNullOrEmpty(VolumeId))
            VolumeId = Guid.NewGuid().ToString("N");
        return VolumeId;
    }

    /// <summary>共有 v2 モード（GroupKey epoch 運用中）か。</summary>
    public bool IsGroupE2ee => KeyEpoch >= 1;

    /// <summary>指定 epoch の GroupKey wraps エントリを取得。無ければ null。</summary>
    public GroupEpochEntry? GetGroupEpoch(int epoch)
        => GroupKeyEpochs.FirstOrDefault(e => e.Epoch == epoch);

    /// <summary>指定ユーザー宛ての、指定 epoch の GroupKey wrap を取得。無ければ null。</summary>
    public UserWrappedKey? GetGroupKeyWrap(int epoch, string username)
        => GetGroupEpoch(epoch)?.Wraps.GetValueOrDefault(username);

    /// <summary>
    /// 新しい GroupKey epoch を登録する。wraps は remaining members 分のみ
    /// （削除されたメンバー宛ての wrap を含めてはならない — クライアント側で生成）。
    /// </summary>
    public GroupEpochEntry AddGroupEpoch(int epoch, Dictionary<string, UserWrappedKey> wraps)
    {
        if (GetGroupEpoch(epoch) is not null)
            throw new VolumeException($"GroupKey epoch {epoch} は既に存在します。");
        var entry = new GroupEpochEntry { Epoch = epoch, Wraps = wraps };
        GroupKeyEpochs.Add(entry);
        KeyEpoch = epoch;
        return entry;
    }

    /// <summary>指定ユーザーの全鍵エントリ（UserKeys + 全 epoch の GroupKey wraps）を削除（revoke）。</summary>
    public bool RemoveUserEverywhere(string username)
    {
        bool removed = UserKeys.Remove(username);
        foreach (var entry in GroupKeyEpochs)
            removed |= entry.Wraps.Remove(username);
        return removed;
    }

    /// <summary>
    /// crypto format v2: 現行 epoch の GroupKey wraps にメンバー追加分の wrap を登録する。
    /// rotation は伴わない（追加メンバーは現行 epoch 以降のデータのみ読める — 追加は新データ権限のみ）。
    /// 旧 epoch の wraps は不変。既に wrap を持つユーザーは拒否（誤って別の GroupKey で上書きしないため）。
    /// </summary>
    public void AddGroupKeyWrap(int epoch, string username, UserWrappedKey wrappedKey)
    {
        if (epoch != KeyEpoch)
            throw new VolumeException($"epoch {epoch} は現行 epoch（{KeyEpoch}）ではありません。");
        var entry = GetGroupEpoch(epoch)
            ?? throw new VolumeException($"GroupKey epoch {epoch} が存在しません（共有 v2 に移行されていません）。");
        if (entry.Wraps.ContainsKey(username))
            throw new VolumeException($"ユーザー '{username}' は既に epoch {epoch} の GroupKey を持っています。");
        entry.Wraps[username] = wrappedKey;
    }

    public bool IsE2ee => EncryptionMode == "e2ee";

    /// <summary>CipherAlgorithm 文字列をパースした実効値。未設定時は AES-256-XTS。</summary>
    public CistaNAS.Shared.Crypto.CipherAlgorithm EffectiveCipherAlgorithm =>
        string.IsNullOrEmpty(CipherAlgorithm)
            ? CistaNAS.Shared.Crypto.CipherAlgorithm.Aes256Xts
            : CipherAlgorithmExtensions.ParseCipherAlgorithm(CipherAlgorithm);

    /// <summary>実効セクタサイズ（バイト）。未設定時は 4096。</summary>
    public int EffectiveSectorSize => SectorSize > 0 ? SectorSize : 4096;

    /// <summary>実効サーバーチャンクサイズ（バイト）。未設定時は 4 MiB。</summary>
    public int EffectiveServerChunkSize => ServerChunkSize > 0 ? ServerChunkSize : 4194304;

    /// <summary>
    /// KEK 導出: KDF スペックに応じて Argon2id+PBKDF2 合成 / Argon2id 単独 / レガシー PBKDF2 単段を使い分ける。
    /// ソルトは SHA256(username) || salt（ユーザー名がソルトの一部 → 同じパスワードでもユーザー違いで別 KEK）。
    /// ヘッダ保存の Argon2id パラメータは上限チェックする（改ざんによるメモリ/CPU DoS 対策）。
    /// </summary>
    private static byte[] DeriveKek(string username, string password, byte[] salt, KdfSpec spec)
    {
        if (spec.IsArgon2Family && !spec.IsValidArgon2Family())
            throw new InvalidDataException("ボリュームヘッダの Argon2id KDF パラメータが上限を超えています。");
        return KeyDerivation.DeriveKek(username, password, salt, spec, KekSize);
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
        string name, string? username, string? password, int sectorSize, KdfSpec kdf, bool encrypted = true, string cipherAlgorithm = "aes-256-xts")
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
                CipherAlgorithm = cipherAlgorithm,
                KeySize = GetKeySize(cipherAlgorithm),
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
            CipherAlgorithm = cipherAlgorithm,
            KeySize = GetKeySize(cipherAlgorithm),
        };
        header.AddUserWrap(username, password, master, kdf);
        return (header, master);
    }

    /// <summary>暗号化アルゴリズムから鍵長を取得。</summary>
    private static int GetKeySize(string cipherAlgorithm) => cipherAlgorithm switch
    {
        "aes-256-xts" => 256,
        "aes-256-gcm" => 256,
        "chacha20-xts" => 256,
        "chacha20-poly1305" => 256,
        _ => 256,  // デフォルト
    };

    /// <summary>追加ユーザーのためにマスター鍵をラップして登録。</summary>
    public void AddUserWrap(string username, string password, byte[] masterKey, KdfSpec kdf)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentException.ThrowIfNullOrEmpty(password);

        byte[] salt = KeyDerivation.NewSalt();
        byte[] kek = DeriveKek(username, password, salt, kdf);
        try
        {
            var (nonce, ct, tag) = WrapKey(masterKey, kek);
            UserKeys[username] = new UserWrappedKey
            {
                Kdf = KdfParams.FromSpec(kdf, salt),
                WrappedMasterKey = new WrappedKey { Nonce = nonce, Ciphertext = ct, Tag = tag },
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>指定ユーザーのエントリを新しいパスワードで再ラップ。</summary>
    public void RewrapUser(string username, string oldPassword, string newPassword, KdfSpec kdf)
    {
        if (!UserKeys.TryGetValue(username, out var entry))
            throw new VolumeException($"ユーザー '{username}' はこのボリュームにアクセス権がありません。");

        byte[] oldKek = DeriveKek(username, oldPassword, entry.Kdf.Salt, entry.Kdf.ToKdfSpec());
        try
        {
            byte[] masterKey = UnwrapKey(entry.WrappedMasterKey, oldKek);
            try
            {
                // 新しいソルトで再ラップ（KDF も現行スペックへ昇格）
                byte[] newSalt = KeyDerivation.NewSalt();
                byte[] newKek = DeriveKek(username, newPassword, newSalt, kdf);
                try
                {
                    var (nonce, ct, tag) = WrapKey(masterKey, newKek);
                    UserKeys[username] = new UserWrappedKey
                    {
                        Kdf = KdfParams.FromSpec(kdf, newSalt),
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

        byte[] kek;
        try
        {
            kek = DeriveKek(username, password, entry.Kdf.Salt, entry.Kdf.ToKdfSpec());
        }
        catch (ArgumentException)
        {
            // ヘッダの KDF パラメータ不正（仕様範囲外）→ パスワード誤りと同様に扱う
            return null;
        }
        catch (InvalidDataException)
        {
            // ヘッダの Argon2id パラメータが検証上限超（改ざん疑い）
            return null;
        }
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
