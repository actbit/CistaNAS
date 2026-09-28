namespace CistaNAS.Client.Services;

/// <summary>
/// 旧バージョンが %APPDATA%/CistaNAS/ecdh_private_{username}.bin（DPAPI 保護）に
/// 保存していた ECDH 秘密鍵ファイルの検出・削除。
///
/// 新方式では ECDH 秘密鍵を永続化ストレージへ保存しない（E2EE パスワードから必要時に
/// 決定論的に再導出する）。旧ファイルは通常コードパスからは読まれず、
/// 「E2EE 共有の保存方式が変更された」旨の警告をユーザーへ表示した上で、
/// 新方式のセットアップ完了後に削除する（無言削除で既存データを突然読めなくさせない）。
/// </summary>
public static class LegacyEcdhKeyCleanup
{
    private static readonly string AppDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CistaNAS");

    /// <summary>残留している旧 ECDH 秘密鍵ファイルの一覧。無ければ空配列。</summary>
    public static string[] DetectLegacyKeyFiles()
    {
        try
        {
            return Directory.Exists(AppDir)
                ? Directory.GetFiles(AppDir, "ecdh_private_*.bin")
                : [];
        }
        catch
        {
            return [];
        }
    }

    /// <summary>旧 ECDH 秘密鍵ファイルを削除する（ユーザーへの警告後 / 新方式セットアップ後に呼ぶこと）。</summary>
    public static int DeleteLegacyKeyFiles()
    {
        int deleted = 0;
        foreach (string path in DetectLegacyKeyFiles())
        {
            try
            {
                File.Delete(path);
                deleted++;
            }
            catch
            {
                // 削除失敗（ロック中等）は次回起動時に再検出される
            }
        }
        return deleted;
    }
}
