using System.Security.Cryptography;
using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Client.Services;

/// <summary>
/// E2EE パスワードからの決定論的 ECDH identity 導出ヘルパー（Desktop）。
///
/// 秘密鍵は永続化ストレージに保存されない。必要時に E2EE Key Password から導出し、
/// 使用後に破棄する（RAM 上のみ）。導出結果はサーバー登録済み公開鍵と照合し、
/// 一致しない（= E2EE パスワードが誤っている）場合は例外で中止する
/// — 誤った identity での unwrap を行わず、登録済み公開鍵を変更しない。
/// </summary>
public static class EcdhIdentityUnlock
{
    public static KdfSpec ToKdfSpec(KdfInfo info)
        => new(info.Algorithm, info.Iterations, info.MemoryKiB, info.Parallelism, info.TimeCost);

    /// <summary>
    /// E2EE パスワードから ECDH identity 鍵ペアを導出し、サーバー登録済み公開鍵と照合する。
    /// 公開鍵が未登録（初回セットアップ）の場合は照合をスキップする。
    /// </summary>
    /// <returns>公開鍵（raw 65B）と秘密鍵（SEC1）。秘密鍵は呼び出し側が使用後に zeroize すること。</returns>
    /// <exception cref="InvalidOperationException">E2EE パスワードが誤っている（導出結果が登録済み公開鍵と不一致）。</exception>
    public static (byte[] PublicKey, byte[] PrivateKeySec1) DeriveVerified(
        string username, string password, EcdhIdentitySetupInfo setup)
    {
        var (publicKey, privateKeySec1) = EcdhIdentityKey.DeriveKeyPair(
            username, password, setup.IdentitySalt, ToKdfSpec(setup.Kdf));
        try
        {
            if (setup.PublicKey is not null
                && !string.Equals(setup.PublicKey, Convert.ToBase64String(publicKey), StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "E2EE 共有パスワードが正しくありません。共有鍵のセットアップ時に設定したパスワードを入力してください。");
            }
            return (publicKey, privateKeySec1);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(privateKeySec1);
            throw;
        }
    }

    /// <summary>
    /// ECDH identity のセットアップ情報を取得する。共有機能が無効なアカウントでは null
    /// （セットアップ不要であることを呼び出し元へ示す）。
    /// </summary>
    public static async Task<EcdhIdentitySetupInfo?> GetSetupAsync(CistaNasApiClient api)
        => await api.GetIdentitySetupAsync();
}
