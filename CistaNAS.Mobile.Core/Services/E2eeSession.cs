using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;
using CistaNAS.Mobile.Core.Security;

namespace CistaNAS.Mobile.Core.Services;

/// <summary>
/// 共有 E2EE crypto format v2 のボリューム鍵状態（VolumeId + epoch ごとの GroupKey）。
/// 全て SecureBuffer で保持し、Dispose 時にゼロクリアする。
/// </summary>
public sealed class E2eeV2VolumeState : IDisposable
{
    private readonly Dictionary<int, SecureBuffer> _groupKeys = new();

    public E2eeV2VolumeState(string volumeId, IReadOnlyDictionary<int, byte[]> groupKeys)
    {
        VolumeId = new SecureBuffer(System.Text.Encoding.UTF8.GetBytes(volumeId));
        foreach (var (epoch, key) in groupKeys)
        {
            if (key.Length != E2eeV2.GroupKeySize)
                throw new ArgumentException($"GroupKey epoch {epoch} のサイズが不正です ({key.Length}B)。");
            _groupKeys[epoch] = new SecureBuffer(key);
        }
    }

    public SecureBuffer VolumeId { get; }

    public string VolumeIdString => System.Text.Encoding.UTF8.GetString(VolumeId.Data);

    /// <summary>自分が保持する最新の epoch（新規アップロードに使う）。鍵が無ければ 0。</summary>
    public int CurrentEpoch => _groupKeys.Count == 0 ? 0 : _groupKeys.Keys.Max();

    public bool HasEpoch(int epoch) => _groupKeys.ContainsKey(epoch);

    /// <summary>指定 epoch の GroupKey を取得する (返り値の配列は変更しないこと。セッションが所有する)。</summary>
    public byte[] GetGroupKey(int epoch) =>
        _groupKeys.TryGetValue(epoch, out var buf) ? buf.Data
            : throw new InvalidOperationException($"GroupKey epoch {epoch} がありません（このデータを読む権限がない可能性があります）。");

    public void Dispose()
    {
        VolumeId.Dispose();
        foreach (var buf in _groupKeys.Values)
            buf.Dispose();
        _groupKeys.Clear();
    }
}

/// <summary>
/// E2EE ボリュームのセッション状態 (ボリュームごとの masterKey / chunkSize) を管理する。
/// masterKey は SecureBuffer で保持し、Dispose 時にゼロクリアする。
/// 共有 v2 モードでは <see cref="E2eeV2VolumeState"/> (GroupKey 辞書 + VolumeId) を併せて保持する
/// （masterKey を持たない v2 メンバーは v2 状態のみで読み書きできる）。
/// </summary>
public sealed class E2eeSession : IDisposable
{
    private readonly Dictionary<string, (SecureBuffer Buffer, int ChunkSize)> _keys = new(StringComparer.Ordinal);
    private readonly Dictionary<string, E2eeV2VolumeState> _v2States = new(StringComparer.Ordinal);

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

    /// <summary>
    /// 共有 v2 の GroupKey 状態を登録する。masterKey を持たないメンバーはこれだけで読み書きできる。
    /// </summary>
    public void StoreV2State(string volumeName, string volumeId, IReadOnlyDictionary<int, byte[]> groupKeysByEpoch)
        => _v2States[volumeName] = new E2eeV2VolumeState(volumeId, groupKeysByEpoch);

    public bool HasKey(string volumeName) => _keys.ContainsKey(volumeName);

    /// <summary>共有 v2 状態を持つか（= 共有 v2 ボリュームとしてアンロック済みか）。</summary>
    public bool HasV2State(string volumeName) => _v2States.ContainsKey(volumeName);

    public int GetChunkSize(string volumeName) =>
        _keys.TryGetValue(volumeName, out var v) ? v.ChunkSize : 1048576;

    /// <summary>masterKey を取得する (返り値の配列は変更しないこと。セッションが所有する)。</summary>
    public byte[] GetMasterKey(string volumeName) =>
        _keys.TryGetValue(volumeName, out var v) ? v.Buffer.Data : throw new InvalidOperationException($"ボリューム '{volumeName}' の鍵がありません。");

    /// <summary>共有 v2 状態を取得する。未登録（v1 / 未アンロック）は例外。</summary>
    public E2eeV2VolumeState GetV2State(string volumeName) =>
        _v2States.TryGetValue(volumeName, out var s) ? s
            : throw new InvalidOperationException($"ボリューム '{volumeName}' の共有 v2 鍵がありません。");

    /// <summary>共有 v2 状態の取得を試みる。</summary>
    public bool TryGetV2State(string volumeName, out E2eeV2VolumeState? state)
    {
        if (_v2States.TryGetValue(volumeName, out var s)) { state = s; return true; }
        state = null;
        return false;
    }

    /// <summary>セッションから鍵を削除してゼロクリアする (ロック時)。</summary>
    public bool RemoveKey(string volumeName)
    {
        bool removed = false;
        if (_keys.Remove(volumeName, out var v))
        {
            v.Buffer.Dispose();
            removed = true;
        }
        if (_v2States.Remove(volumeName, out var v2))
        {
            v2.Dispose();
            removed = true;
        }
        return removed;
    }

    /// <summary>全ボリュームの鍵をゼロクリアする (ログアウト時)。セッション自体は継続利用可能。</summary>
    public void ClearKeys()
    {
        foreach (var v in _keys.Values)
            v.Buffer.Dispose();
        _keys.Clear();
        foreach (var v2 in _v2States.Values)
            v2.Dispose();
        _v2States.Clear();
    }

    public void Dispose()
    {
        foreach (var v in _keys.Values)
            v.Buffer.Dispose();
        _keys.Clear();
        foreach (var v2 in _v2States.Values)
            v2.Dispose();
        _v2States.Clear();
    }
}
