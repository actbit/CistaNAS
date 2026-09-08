namespace CistaNAS.Mobile.Core.Abstractions;

/// <summary>
/// 非機密のアプリ設定 (サーバー URL・ユーザー名等) の永続化。
/// JWT やパスワードはここに置かない (JWT はメモリのみ、パスワードは ISecureKeyStore)。
/// </summary>
public interface IAppSettings
{
    string? ServerUrl { get; set; }
    string? Username { get; set; }

    /// <summary>設定を永続化する。</summary>
    void Save();
}
