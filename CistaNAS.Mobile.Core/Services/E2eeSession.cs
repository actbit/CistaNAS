using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;
using CistaNAS.Mobile.Core.Security;

namespace CistaNAS.Mobile.Core.Services;

/// <summary>
/// E2EE ボリュームのセッション状態 (ボリュームごとの masterKey / chunkSize) を管理する。
/// masterKey は SecureBuffer で保持し、Dispose 時にゼロクリアする。
/// </summary>
public sealed class E2eeSession : IDisposable
{
    private readonly Dictionary<string, (SecureBuffer Buffer, int ChunkSize)> _keys = new(StringComparer.Ordinal);

    /// <summary>wrapped-key を復号 (アンラップ) して masterKey を取得する。</summary>
    /// <param name="username">KEK 導出に使うユーザー名。</param>
    /// <param name="password">ボリュームパスワード (wrapType=password 時に使用)。</param>
    /// <param name="wk">サーバーから取得した wrapped key。</param>
    /// <param name="ecdhPrivateKey">wrapType=ecdh 時の自分の ECDH 秘密鍵 (SEC1)。</param>
    public byte[] UnwrapMasterKey(string username, string? password, WrappedKeyInfo wk, byte[]? ecdhPrivateKey)
    {
        switch (wk.WrapType)
        {
            case "ecdh":
            {
                if (ecdhPrivateKey is null || wk.EphemeralPublicKey is null)
                    throw new InvalidOperationException("ECDH 鍵ペアが未登録のため、このボリュームを復号できません。");
                return E2eeCrypto.EcdhUnwrap(wk.WrappedNonce, wk.WrappedCiphertext, wk.WrappedTag, wk.EphemeralPublicKey, ecdhPrivateKey);
            }
            case null:
            case "password":
            {
                if (string.IsNullOrEmpty(password))
                    throw new InvalidOperationException("ボリュームパスワードが必要です。");
                // ヘッダの KDF スペック（Argon2id 合成 / レガシー PBKDF2）で KEK を導出
                byte[] kek = E2eeCrypto.DeriveKek(username, password, wk.KdfSalt, new KdfSpec(
                    wk.KdfAlgorithm, wk.KdfIterations, wk.KdfMemoryKiB, wk.KdfParallelism, wk.KdfTimeCost));
                try
                {
                    return E2eeCrypto.UnwrapMasterKey(wk.WrappedNonce, wk.WrappedCiphertext, wk.WrappedTag, kek, wk.KdfAlgorithm == "chacha20-poly1305" ? "chacha20-poly1305" : "aes-256-gcm");
                }
                finally
                {
                    Array.Clear(kek);
                }
            }
            default:
                throw new NotSupportedException($"wrapType '{wk.WrapType}' は未対応です。");
        }
    }

    /// <summary>アンラップ済み masterKey をセッションに登録する。</summary>
    public void StoreKey(string volumeName, byte[] masterKey, int chunkSize)
    {
        _keys[volumeName] = (new SecureBuffer(masterKey), chunkSize);
    }

    public bool HasKey(string volumeName) => _keys.ContainsKey(volumeName);

    public int GetChunkSize(string volumeName) =>
        _keys.TryGetValue(volumeName, out var v) ? v.ChunkSize : 1048576;

    /// <summary>masterKey を取得する (返り値の配列は変更しないこと。セッションが所有する)。</summary>
    public byte[] GetMasterKey(string volumeName) =>
        _keys.TryGetValue(volumeName, out var v) ? v.Buffer.Data : throw new InvalidOperationException($"ボリューム '{volumeName}' の鍵がありません。");

    /// <summary>セッションから鍵を削除してゼロクリアする (ロック時)。</summary>
    public bool RemoveKey(string volumeName)
    {
        if (!_keys.Remove(volumeName, out var v)) return false;
        v.Buffer.Dispose();
        return true;
    }

    /// <summary>全ボリュームの鍵をゼロクリアする (ログアウト時)。セッション自体は継続利用可能。</summary>
    public void ClearKeys()
    {
        foreach (var v in _keys.Values)
            v.Buffer.Dispose();
        _keys.Clear();
    }

    public void Dispose()
    {
        foreach (var v in _keys.Values)
            v.Buffer.Dispose();
        _keys.Clear();
    }
}
