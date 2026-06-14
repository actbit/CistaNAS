using System.Security.Cryptography;

namespace CistaNAS.Client.Services;

/// <summary>
/// ECDH 秘密鍵を DPAPI (CurrentUser スコープ) で保護してローカルに永続化する。
/// 保存先: %APPDATA%/CistaNAS/ecdh_private_{username}.bin
/// 被共有者（group-e2ee の招待/共有を受けたユーザー）がマウント時に
/// 自分の ECDH 秘密鍵でラップキーをアンラップするために使用する。
/// </summary>
public static class EcdhKeyStore
{
    private static readonly string AppDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "CistaNAS");

    private static string GetPath(string username)
    {
        // ユーザー名にファイル名へ使えない文字が含まれる場合に置換
        string safe = string.Concat(username.Select(c =>
            char.IsLetterOrDigit(c) || c == '-' || c == '_' ? c : '_'));
        return Path.Combine(AppDir, $"ecdh_private_{safe}.bin");
    }

    /// <summary>ECDH 秘密鍵（SEC1）を DPAPI で保護して保存する。</summary>
    public static void SavePrivateKey(string username, byte[] privateKeySec1)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentNullException.ThrowIfNull(privateKeySec1);

        Directory.CreateDirectory(AppDir);
        byte[] encrypted = ProtectedData.Protect(privateKeySec1, null, DataProtectionScope.CurrentUser);

        string path = GetPath(username);
        string tmp = path + ".tmp";
        File.WriteAllBytes(tmp, encrypted);
        File.Move(tmp, path, overwrite: true);
    }

    /// <summary>ECDH 秘密鍵を読み込む。未登録や復号失敗時は null。</summary>
    public static byte[]? LoadPrivateKey(string username)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);

        string path = GetPath(username);
        if (!File.Exists(path)) return null;

        byte[] encrypted = File.ReadAllBytes(path);
        try
        {
            return ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException)
        {
            // 別 Windows ユーザーコンテキストやファイル改ざん等で復号失敗
            return null;
        }
    }

    /// <summary>秘密鍵を削除する（鍵ペア再生成時等）。</summary>
    public static void DeletePrivateKey(string username)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);

        string path = GetPath(username);
        if (File.Exists(path)) File.Delete(path);
    }

    /// <summary>秘密鍵が登録済みか。</summary>
    public static bool HasPrivateKey(string username) => File.Exists(GetPath(username));
}
