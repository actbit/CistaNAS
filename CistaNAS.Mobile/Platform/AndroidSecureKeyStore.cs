using Android.Content;
using Android.Security.Keystore;
using CistaNAS.Mobile.Core.Abstractions;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;

namespace CistaNAS.Mobile.Platform;

/// <summary>
/// AndroidKeyStore の非エクスポート AES-256-GCM 鍵で暗号化して
/// アプリ内ストレージ (FilesDir/secrets) に保存する ISecureKeyStore。
/// 保存形式: [version:1B][nonce:12B][ciphertext+tag]。書き込みは tmp → rename でアトミック。
/// (Desktop Client の DPAPI EcdhKeyStore と同じ役割。)
/// </summary>
public sealed class AndroidSecureKeyStore : ISecureKeyStore
{
    private const string KeyAlias = "cistanas-storage-key";
    private const string Provider = "AndroidKeyStore";
    private const byte FormatVersion = 1;

    private static readonly object Gate = new();
    private static readonly string SecretsDir =
        Path.Combine(Application.Context.FilesDir!.Path!, "secrets");

    public byte[]? Load(string name)
    {
        string file = SafePath(name);
        lock (Gate)
        {
            if (!File.Exists(file)) return null;
            byte[] blob = File.ReadAllBytes(file);
            if (blob.Length < 1 + 12 + 16 || blob[0] != FormatVersion)
                return null;
            try
            {
                byte[] nonce = blob[1..13];
                byte[] encrypted = blob[13..];
                using Cipher cipher = Cipher.GetInstance("AES/GCM/NoPadding")!;
                cipher.Init(CipherMode.DecryptMode, GetOrCreateKey(), new GCMParameterSpec(128, nonce));
                return cipher.DoFinal(encrypted);
            }
            catch (Java.Security.GeneralSecurityException)
            {
                // 端末内鍵の再生成等で復号不能になった場合は存在しないものとして扱う
                return null;
            }
        }
    }

    public void Save(string name, byte[] plaintext)
    {
        string file = SafePath(name);
        Directory.CreateDirectory(SecretsDir);
        lock (Gate)
        {
            using Cipher cipher = Cipher.GetInstance("AES/GCM/NoPadding")!;
            cipher.Init(CipherMode.EncryptMode, GetOrCreateKey());
            byte[] nonce = cipher.GetIV()!;
            byte[] encrypted = cipher.DoFinal(plaintext)!;

            using var ms = new MemoryStream(1 + nonce.Length + encrypted.Length);
            ms.WriteByte(FormatVersion);
            ms.Write(nonce);
            ms.Write(encrypted);

            string tmp = file + ".tmp";
            File.WriteAllBytes(tmp, ms.ToArray());
            File.Move(tmp, file, overwrite: true);
        }
    }

    public void Delete(string name)
    {
        string file = SafePath(name);
        lock (Gate)
        {
            if (File.Exists(file)) File.Delete(file);
        }
    }

    public bool Exists(string name) => File.Exists(SafePath(name));

    private static string SafePath(string name)
    {
        foreach (char c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return Path.Combine(SecretsDir, name + ".bin");
    }

    /// <summary>AndroidKeyStore から鍵を取得する。無ければ AES-256-GCM の非エクスポート鍵を生成する。</summary>
    private static ISecretKey GetOrCreateKey()
    {
        using KeyStore ks = KeyStore.GetInstance(Provider)!;
        ks.Load(null);
        ISecretKey? existing = ks.GetKey(KeyAlias, null) as ISecretKey;
        if (existing is not null) return existing;

        // バインディングに列挙型オーバーロードがないため KeyProperties の文字列定数を使う
        var spec = new KeyGenParameterSpec.Builder(
                KeyAlias,
                KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
            .SetBlockModes(KeyProperties.BlockModeGcm)
            .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)
            .SetKeySize(256)
            .Build();

        using KeyGenerator generator = KeyGenerator.GetInstance("AES", Provider)!;
        generator.Init(spec);
        return generator.GenerateKey()!;
    }
}
