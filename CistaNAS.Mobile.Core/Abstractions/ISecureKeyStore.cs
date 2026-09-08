namespace CistaNAS.Mobile.Core.Abstractions;

/// <summary>
/// 機密データ (ECDH 秘密鍵等) の保護付き永続化。
/// Android 実装では AndroidKeyStore の AES-GCM 鍵で暗号化して保存する。
/// </summary>
public interface ISecureKeyStore
{
    /// <summary>指定名のデータを読み込む。存在しなければ null。</summary>
    byte[]? Load(string name);

    /// <summary>指定名でデータを保護保存する。</summary>
    void Save(string name, byte[] plaintext);

    /// <summary>指定名のデータを削除する。</summary>
    void Delete(string name);

    /// <summary>指定名のデータが存在するか。</summary>
    bool Exists(string name);
}
