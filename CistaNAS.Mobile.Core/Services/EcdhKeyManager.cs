using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;
using CistaNAS.Mobile.Core.Abstractions;

namespace CistaNAS.Mobile.Core.Services;

/// <summary>
/// E2EE 用 ECDH (P-256) 鍵ペアの管理。
/// 秘密鍵は <see cref="ISecureKeyStore"/> (AndroidKeyStore ラップ) に保存し、
/// 公開鍵はサーバーに登録する。デスクトップクライアント (DPAPI) と同型の鍵を使用する。
/// </summary>
public sealed class EcdhKeyManager(ISecureKeyStore keyStore)
{
    private const string KeyNamePrefix = "ecdh_priv_";

    private static string KeyName(string username) => KeyNamePrefix + username;

    /// <summary>
    /// ECDH 秘密鍵を取得する。無ければ生成してサーバーに公開鍵を登録する。
    /// </summary>
    /// <returns>秘密鍵 (SEC1)。戻り値の配列は呼び出し側が責任を持って破棄すること。</returns>
    public async Task<byte[]> GetOrCreatePrivateKeyAsync(CistaNasApiClient api, string username)
    {
        string name = KeyName(username);
        byte[]? stored = keyStore.Load(name);
        if (stored is not null)
        {
            // サーバーに公開鍵が未登録の場合は登録する (端末移行後の再初期化に対応)
            string? serverKey = await api.GetPublicKeyAsync(username);
            if (serverKey is null)
            {
                await api.SetMyPublicKeyAsync(GetRawPublicKey(stored));
            }
            return stored;
        }

        var (newPublic, newPrivate) = E2eeCrypto.GenerateEcdhKeyPair();
        keyStore.Save(name, newPrivate);
        await api.SetMyPublicKeyAsync(newPublic);
        return newPrivate;
    }

    /// <summary>SEC1 秘密鍵から raw 非圧縮公開鍵 (0x04||X||Y, 65B) を取り出す。</summary>
    public static byte[] GetRawPublicKey(byte[] sec1PrivateKey)
    {
        using var ecdh = System.Security.Cryptography.ECDiffieHellman.Create();
        ecdh.ImportECPrivateKey(sec1PrivateKey, out _);
        var q = ecdh.ExportParameters(false).Q;
        byte[] pub = new byte[65];
        pub[0] = 0x04;
        q.X.AsSpan().CopyTo(pub.AsSpan(1));
        q.Y.AsSpan().CopyTo(pub.AsSpan(33));
        return pub;
    }

    /// <summary>指定ユーザーの鍵ペアを削除する (鍵再登録用)。</summary>
    public void DeletePrivateKey(string username) => keyStore.Delete(KeyName(username));

    public bool HasPrivateKey(string username) => keyStore.Exists(KeyName(username));
}
