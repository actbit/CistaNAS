using CistaNAS.Wasm.Models;
using Microsoft.JSInterop;

namespace CistaNAS.Wasm.Services;

/// <summary>公開鍵 pin（TOFU trust anchor）検証の結果。</summary>
public enum PinCheckResult
{
    /// <summary>初回使用: fingerprint を記録して保存した。</summary>
    Created,
    /// <summary>既存 pin と fingerprint が一致。</summary>
    Match,
    /// <summary>既存 pin と fingerprint が不一致（呼び出し側は操作を中断し、ユーザーに警告すること）。</summary>
    Mismatch,
}

/// <summary>
/// 共有 E2EE の鍵解決オーケストレーション。
/// E2EE 秘密鍵（localStorage + password 復号）・masterKey wrap・GroupKey wraps（crypto format v2）の
/// アンラップ、公開鍵 pinning 検証（IndexedDB、origin ローカル保存）を Blazor Pages から集約する
/// （CLAUDE.md のレイヤー規約）。pin / 秘密鍵 / fingerprint がサーバーに保存されることはない。
/// </summary>
public sealed class E2eeKeyResolverService(E2eeInterop e2ee, VolumeApiClient volumeApi, IJSRuntime js)
{
    private readonly E2eeInterop _e2ee = e2ee;
    private readonly VolumeApiClient _volumeApi = volumeApi;
    private readonly IJSRuntime _js = js;

    // ---- E2EE 秘密鍵 / masterKey ----

    /// <summary>localStorage の E2EE 秘密鍵を password で復号してハンドルを返す。未登録・password 不正時は例外。</summary>
    public async Task<string> LoadPrivateKeyAsync(string username, string password)
    {
        string privJson = await _js.InvokeAsync<string>("localStorage.getItem", $"e2ee_privkey_{username}");
        if (string.IsNullOrEmpty(privJson))
            throw new Exception("ローカルに E2EE 秘密鍵が見つかりません。先に設定ページで E2EE 鍵ペアを生成してください。");
        using var privDoc = System.Text.Json.JsonDocument.Parse(privJson);
        var privRoot = privDoc.RootElement;
        try
        {
            return await _e2ee.DecryptPrivateKey(
                privRoot.GetProperty("wrapped").GetString()!,
                privRoot.GetProperty("nonce").GetString()!,
                password,
                privRoot.GetProperty("salt").GetString()!,
                E2eeInterop.ReadPrivKeyKdf(privRoot));
        }
        catch
        {
            throw new Exception("E2EE 鍵ペアのパスワードが正しくありません。E2EE 鍵ペア生成時のパスワードを入力してください。");
        }
    }

    /// <summary>自分宛ての wrapped masterKey をアンラップしてハンドルを返す
    /// （ECDH wrap は E2EE 秘密鍵、password wrap は KEK 導出でアンラップ）。</summary>
    public async Task<string> UnwrapMyMasterKeyAsync(WrappedKeyResponse wrappedKeyResp, string username, string password)
    {
        if (string.Equals(wrappedKeyResp.WrapType, "ecdh", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(wrappedKeyResp.EphemeralPublicKey))
                throw new Exception("ECDH ラップキーに一時公開鍵が含まれていません。");
            string privHandle = await LoadPrivateKeyAsync(username, password);
            try
            {
                return await _e2ee.EcdhUnwrap(
                    wrappedKeyResp.WrappedMasterKey.Nonce,
                    wrappedKeyResp.WrappedMasterKey.Ciphertext,
                    wrappedKeyResp.WrappedMasterKey.Tag,
                    wrappedKeyResp.EphemeralPublicKey,
                    privHandle);
            }
            finally
            {
                try { await _e2ee.ClearKey(privHandle); } catch { }
            }
        }

        string kekHandle = await _e2ee.DeriveKek(password,
            wrappedKeyResp.Kdf.Salt,
            new E2eeKdfOptions(wrappedKeyResp.Kdf.Algorithm, wrappedKeyResp.Kdf.Iterations,
                wrappedKeyResp.Kdf.MemoryKiB, wrappedKeyResp.Kdf.TimeCost, wrappedKeyResp.Kdf.Parallelism),
            username);
        try
        {
            return await _e2ee.UnwrapMasterKey(
                wrappedKeyResp.WrappedMasterKey.Nonce,
                wrappedKeyResp.WrappedMasterKey.Ciphertext,
                wrappedKeyResp.WrappedMasterKey.Tag,
                kekHandle);
        }
        finally
        {
            try { await _e2ee.ClearKey(kekHandle); } catch { }
        }
    }

    // ---- 公開鍵 pinning（TOFU trust anchor）----

    /// <summary>
    /// TOFU pin 検証。pin 未登録なら fingerprint を記録して保存（初回使用）。
    /// 登録済みで fingerprint が一致しない場合は Mismatch を返す — 呼び出し側は操作を中断し、
    /// ユーザーに警告すること（自動的には新しい鍵を信頼しない。pin 更新はユーザーの明示操作のみ）。
    /// pin はこのブラウザの IndexedDB にのみ保存され、サーバーには送信されない。
    /// </summary>
    public async Task<(PinCheckResult Result, PinRecord? ExistingPin, string Fingerprint)> CheckPinAsync(
        string username, string publicKeyBase64)
    {
        string fingerprint = await _e2ee.ComputeFingerprint(publicKeyBase64);
        var pin = await _e2ee.GetPinAsync(username);
        if (pin is null)
        {
            await _e2ee.PutPinAsync(username, fingerprint);
            return (PinCheckResult.Created, null, fingerprint);
        }
        if (!string.Equals(pin.FingerprintSha256, fingerprint, StringComparison.Ordinal))
            return (PinCheckResult.Mismatch, pin, fingerprint);
        return (PinCheckResult.Match, pin, fingerprint);
    }

    /// <summary>pin 不一致検知後の明示的な pin 更新（新しい鍵を信頼する）。ユーザーの明示操作からのみ呼ぶこと。</summary>
    public Task TrustNewKeyAsync(string username, string fingerprint)
        => _e2ee.PutPinAsync(username, fingerprint);

    // ---- 共有 v2: GroupKey ----

    /// <summary>自分宛ての GroupKey wrap を E2EE 秘密鍵（password 復号）でアンラップして base64 を返す。</summary>
    public async Task<string> UnwrapGroupKeyAsync(GroupKeyWrapInfoJson wrap, string volumeId, string username, string password)
    {
        if (!string.Equals(wrap.WrapType, "ecdh", StringComparison.OrdinalIgnoreCase) || wrap.EphemeralPublicKey is null)
            throw new Exception($"GroupKey wrap（epoch {wrap.Epoch}）の形式が不正です。");
        string privHandle = await LoadPrivateKeyAsync(username, password);
        try
        {
            return await _e2ee.EcdhUnwrapGroupKey(
                Convert.ToBase64String(wrap.Nonce),
                Convert.ToBase64String(wrap.Ciphertext),
                Convert.ToBase64String(wrap.Tag),
                wrap.EphemeralPublicKey, privHandle,
                volumeId, wrap.Epoch, username);
        }
        finally
        {
            try { await _e2ee.ClearKey(privHandle); } catch { }
        }
    }

    /// <summary>
    /// 自分宛ての全 epoch GroupKey をアンラップする。v2 未移行ボリューム（group-key-info 無し /
    /// KeyEpoch == 0）では (空, null) を返す。1 epoch 分の復号失敗は無視する
    /// （その epoch のファイルのみダウンロード時にエラーになる）。
    /// </summary>
    public async Task<(IReadOnlyDictionary<int, string> GroupKeys, string? VolumeId)> LoadGroupKeysAsync(
        string volumeName, string username, string password)
    {
        var groupKeys = new Dictionary<int, string>();
        E2eeGroupKeyInfoResponse? gki;
        try { gki = await _volumeApi.GetGroupKeyInfoAsync(volumeName); }
        catch { return (groupKeys, null); }
        if (gki is null || gki.KeyEpoch == 0) return (groupKeys, null);

        foreach (var wrapInfo in gki.MyGroupKeys)
        {
            if (wrapInfo.Epoch <= 0) continue;
            try
            {
                groupKeys[wrapInfo.Epoch] = await UnwrapGroupKeyAsync(wrapInfo, gki.VolumeId, username, password);
            }
            catch { /* この epoch のみ読めない。ダウンロード時に明示的なエラーになる */ }
        }
        return (groupKeys, gki.VolumeId);
    }
}
