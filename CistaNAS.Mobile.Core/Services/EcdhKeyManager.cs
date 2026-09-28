using System.Security.Cryptography;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Abstractions;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Mobile.Core.Services;

/// <summary>
/// E2EE 用 ECDH (P-256) identity 鍵の決定論的導出。
///
/// 秘密鍵はランダム生成して <see cref="ISecureKeyStore"/> (AndroidKeyStore ラップ) に
/// 保存するのではなく、username / E2EE Key Password / identity salt から必要時に
/// 決定論的に導出する（<see cref="EcdhIdentityKey"/>。Desktop / WASM と同一仕様）。
/// 秘密鍵は RAM 上のみに存在し、secure store を含む永続化ストレージへは一切書き込まない。
/// 導出結果はサーバー登録済み公開鍵と照合し、一致しない（= パスワード誤り）場合は
/// 例外で中止する — 誤った identity での unwrap を行わず、登録済み公開鍵を変更しない。
/// </summary>
public sealed class EcdhKeyManager
{
    private static KdfSpec ToKdfSpec(KdfInfo info)
        => new(info.Algorithm, info.Iterations, info.MemoryKiB, info.Parallelism, info.TimeCost);

    /// <summary>
    /// identity のセットアップ情報を取得する。共有機能が無効なアカウントでは null
    /// （セットアップ不要であることを呼び出し元へ示す。私用 E2EE ボリュームは共有無効でも利用可能）。
    /// </summary>
    public static async Task<EcdhIdentitySetupInfo?> GetSetupAsync(CistaNasApiClient api)
        => await api.GetIdentitySetupAsync();

    /// <summary>
    /// E2EE Key Password から ECDH identity 鍵ペアを導出し、サーバー登録済み公開鍵と照合する。
    /// 公開鍵が未登録（初回セットアップ）の場合は照合をスキップする。
    /// 戻り値の秘密鍵 (SEC1) は秘密情報であり、呼び出し側は使用後に Array.Clear 等で破棄すること。
    /// </summary>
    /// <exception cref="InvalidOperationException">E2EE Key Password が誤っている、または共有機能が無効。</exception>
    public async Task<(byte[] PublicKey, byte[] PrivateKeySec1)> DeriveVerifiedAsync(
        CistaNasApiClient api, string username, string e2eePassword)
    {
        if (string.IsNullOrEmpty(e2eePassword))
            throw new InvalidOperationException("E2EE Key Password を入力してください。");
        var setup = await api.GetIdentitySetupAsync()
            ?? throw new InvalidOperationException(
                "このアカウントでは共有機能が無効です。E2EE 共有のセットアップはできません。");
        var (publicKey, privateKeySec1) = EcdhIdentityKey.DeriveKeyPair(
            username, e2eePassword, setup.IdentitySalt, ToKdfSpec(setup.Kdf));
        try
        {
            if (setup.PublicKey is not null
                && !string.Equals(setup.PublicKey, Convert.ToBase64String(publicKey), StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "E2EE Key Password が正しくありません。共有鍵セットアップ時に設定したパスワードを入力してください。");
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
    /// identity 鍵を導出し、公開鍵が未登録ならサーバーに登録する（初回セットアップ）。
    /// 既存鍵の更新（rotation）は行わない — パスワード誤りで既存 identity を上書きしないため。
    /// </summary>
    public async Task<byte[]> SetupIdentityKeyAsync(CistaNasApiClient api, string username, string e2eePassword)
    {
        var (publicKey, privateKeySec1) = await DeriveVerifiedAsync(api, username, e2eePassword);
        try
        {
            CryptographicOperations.ZeroMemory(privateKeySec1);
            string? serverKey = await api.GetPublicKeyAsync(username);
            if (serverKey is null)
                await api.SetMyPublicKeyAsync(publicKey);
            return publicKey;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    /// <summary>
    /// 旧バージョンが secure store に保存した ECDH 秘密鍵 (ecdh_priv_{username}) を検出する。
    /// 新方式では秘密鍵を永続化しないため残留していても使用されない。
    /// </summary>
    public static bool HasLegacySecureStoreKey(ISecureKeyStore keyStore, string username)
        => keyStore.Exists("ecdh_priv_" + username);

    /// <summary>
    /// 旧 secure store の ECDH 秘密鍵を削除する（ユーザーへの警告後の明示操作からのみ呼ぶこと）。
    /// </summary>
    public static void DeleteLegacySecureStoreKey(ISecureKeyStore keyStore, string username)
        => keyStore.Delete("ecdh_priv_" + username);

    /// <summary>SEC1 秘密鍵から raw 非圧縮公開鍵 (0x04||X||Y, 65B) を取り出す。</summary>
    public static byte[] GetRawPublicKey(byte[] sec1PrivateKey)
    {
        using var ecdh = ECDiffieHellman.Create();
        ecdh.ImportECPrivateKey(sec1PrivateKey, out _);
        var q = ecdh.ExportParameters(false).Q;
        byte[] pub = new byte[65];
        pub[0] = 0x04;
        q.X.AsSpan().CopyTo(pub.AsSpan(1));
        q.Y.AsSpan().CopyTo(pub.AsSpan(33));
        return pub;
    }
}
