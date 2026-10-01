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
public sealed class E2eeKeyResolverService(E2eeInterop e2ee, VolumeApiClient volumeApi,
    E2eeApiClient e2eeApi, IJSRuntime js)
{
    private readonly E2eeInterop _e2ee = e2ee;
    private readonly VolumeApiClient _volumeApi = volumeApi;
    private readonly E2eeApiClient _e2eeApi = e2eeApi;
    private readonly IJSRuntime _js = js;

    // ---- E2EE 秘密鍵 / masterKey ----

    /// <summary>
    /// E2EE パスワードから決定論的に ECDH identity 秘密鍵を導出してハンドルを返す。
    /// 秘密鍵は永続化ストレージに存在せず、RAM 上の non-extractable WebCrypto key としてのみ保持する。
    /// 導出結果はサーバー登録済み公開鍵と照合し、不一致（= パスワード誤り）時は例外で中止する
    /// — 誤った identity での unwrap を行わず、登録済み公開鍵を変更しない。
    /// 旧バージョンが localStorage に書き込んだ E2EE 秘密鍵 (e2ee_privkey_*) は検出次第削除する。
    /// </summary>
    public async Task<string> LoadPrivateKeyAsync(string username, string password, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(password))
            throw new Exception("E2EE 共有パスワードを入力してください。");
        ct.ThrowIfCancellationRequested();
        var setup = await _e2eeApi.GetIdentitySetupAsync(ct)
            ?? throw new Exception("このアカウントでは E2EE 共有機能が無効です。");
        // 未対応の DerivationVersion では導出してはならない:
        // 導出仕様が変わったサーバーに対して旧仕様で導出すると、誤った鍵で公開鍵を
        // 登録・更新し、既存 identity を破壊する（データ欠損）。導出前に拒否する
        // （Desktop / Mobile の EcdhIdentityKey.CurrentDerivationVersion と同一の契約）。
        if (setup.DerivationVersion != CistaNAS.Shared.Crypto.EcdhIdentityKey.CurrentDerivationVersion)
            throw new Exception(
                $"サーバーの ECDH identity 導出バージョン (v{setup.DerivationVersion}) はこのクライアント (v{CistaNAS.Shared.Crypto.EcdhIdentityKey.CurrentDerivationVersion}) が未対応です。ページを最新のクライアントで読み込み直してください。");
        var kdf = new E2eeKdfOptions(setup.Kdf.Algorithm, setup.Kdf.Iterations,
            setup.Kdf.MemoryKiB, setup.Kdf.TimeCost, setup.Kdf.Parallelism);
        ct.ThrowIfCancellationRequested();
        var derived = await _e2ee.DeriveIdentityKeyPair(
            username, password, Convert.ToBase64String(setup.IdentitySalt), kdf);
        try
        {
            ct.ThrowIfCancellationRequested();
            if (!string.IsNullOrEmpty(setup.PublicKey)
                && !string.Equals(setup.PublicKey, derived.PublicKeyBase64, StringComparison.Ordinal))
            {
                throw new Exception(
                    "E2EE 共有パスワードが正しくありません。共有鍵セットアップ時に設定したパスワードを入力してください。");
            }
            try { await _e2ee.ClearKey(derived.PublicKeyHandle); } catch { }
            await RemoveLegacyPrivateKeyAsync(username);
            ct.ThrowIfCancellationRequested();
            return derived.PrivateKeyHandle;
        }
        catch
        {
            try { await _e2ee.ClearKey(derived.PublicKeyHandle); } catch { }
            try { await _e2ee.ClearKey(derived.PrivateKeyHandle); } catch { }
            throw;
        }
    }

    /// <summary>
    /// 旧バージョンが localStorage に保存した E2EE 秘密鍵 (e2ee_privkey_*) を検出して削除する。
    /// 新方式では秘密鍵をブラウザに保存しないため、残留した旧鍵は即座に除去する。
    /// </summary>
    public async Task<bool> RemoveLegacyPrivateKeyAsync(string username)
    {
        try
        {
            string key = $"e2ee_privkey_{username}";
            string? legacy = await _js.InvokeAsync<string?>("localStorage.getItem", key);
            if (string.IsNullOrEmpty(legacy)) return false;
            await _js.InvokeVoidAsync("localStorage.removeItem", key);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>旧 localStorage 秘密鍵が残留しているか（Settings ページの警告表示用）。</summary>
    public async Task<bool> HasLegacyPrivateKeyAsync(string username)
    {
        try
        {
            string? legacy = await _js.InvokeAsync<string?>("localStorage.getItem", $"e2ee_privkey_{username}");
            return !string.IsNullOrEmpty(legacy);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>自分宛ての wrapped masterKey をアンラップしてハンドルを返す
    /// （ECDH wrap は E2EE 秘密鍵、password wrap は KEK 導出でアンラップ）。</summary>
    public async Task<string> UnwrapMyMasterKeyAsync(WrappedKeyResponse wrappedKeyResp, string username, string password, CancellationToken ct = default)
    {
        if (string.Equals(wrappedKeyResp.WrapType, "ecdh", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(wrappedKeyResp.EphemeralPublicKey))
                throw new Exception("ECDH ラップキーに一時公開鍵が含まれていません。");
            string privHandle = await LoadPrivateKeyAsync(username, password, ct);
            try
            {
                ct.ThrowIfCancellationRequested();
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

        ct.ThrowIfCancellationRequested();
        string kekHandle = await _e2ee.DeriveKek(password,
            wrappedKeyResp.Kdf.Salt,
            new E2eeKdfOptions(wrappedKeyResp.Kdf.Algorithm, wrappedKeyResp.Kdf.Iterations,
                wrappedKeyResp.Kdf.MemoryKiB, wrappedKeyResp.Kdf.TimeCost, wrappedKeyResp.Kdf.Parallelism),
            username);
        try
        {
            ct.ThrowIfCancellationRequested();
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
    public async Task<string> UnwrapGroupKeyAsync(GroupKeyWrapInfoJson wrap, string volumeId, string username, string password, CancellationToken ct = default)
    {
        if (!string.Equals(wrap.WrapType, "ecdh", StringComparison.OrdinalIgnoreCase) || wrap.EphemeralPublicKey is null)
            throw new Exception($"GroupKey wrap（epoch {wrap.Epoch}）の形式が不正です。");
        string privHandle = await LoadPrivateKeyAsync(username, password, ct);
        try
        {
            ct.ThrowIfCancellationRequested();
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
        string volumeName, string username, string password, CancellationToken ct = default)
    {
        var groupKeys = new Dictionary<int, string>();
        E2eeGroupKeyInfoResponse? gki;
        try { gki = await _volumeApi.GetGroupKeyInfoAsync(volumeName, ct); }
        catch (OperationCanceledException) { throw; }
        catch { return (groupKeys, null); }
        ct.ThrowIfCancellationRequested();
        if (gki is null || gki.KeyEpoch == 0) return (groupKeys, null);

        foreach (var wrapInfo in gki.MyGroupKeys)
        {
            if (wrapInfo.Epoch <= 0) continue;
            try
            {
                groupKeys[wrapInfo.Epoch] = await UnwrapGroupKeyAsync(wrapInfo, gki.VolumeId, username, password, ct);
                ct.ThrowIfCancellationRequested();
            }
            catch (OperationCanceledException) { throw; }
            catch { /* この epoch のみ読めない。ダウンロード時に明示的なエラーになる */ }
        }
        return (groupKeys, gki.VolumeId);
    }
}
