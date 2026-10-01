using CistaNAS.Wasm.Auth;

namespace CistaNAS.Wasm.Services;

/// <summary>画面を開始した認証世代に結び付けたログイン・初回セットアップ。</summary>
public sealed class BrowserAuthenticationService(WasmAuthStateProvider auth, AuthApiClient api, VolumeApiClient volumes)
{
    public long Version => auth.AuthenticationVersion;
    public void EnsureCurrent(long version, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (version != Version) throw new OperationCanceledException("認証状態が変更されました。");
    }

    public async Task<bool> LoginAsync(string username, string password, long version, CancellationToken ct)
    {
        EnsureCurrent(version, ct);
        var result = await api.LoginAsync(username, password, ct);
        EnsureCurrent(version, ct);
        if (result is null) return false;
        await auth.SetTokenAsync(result.AccessToken, result.ExpiresAt);
        EnsureCurrent(version + 1, ct);
        return true;
    }

    public async Task SetupAsync(string username, string password, string? volume, long version, CancellationToken ct)
    {
        EnsureCurrent(version, ct);
        bool created = await api.SetupAsync(username, password, ct);
        EnsureCurrent(version, ct);
        if (!created) throw new InvalidOperationException("既にセットアップ済みです。");
        if (!await LoginAsync(username, password, version, ct))
            throw new InvalidOperationException("管理者を作成しましたがログインに失敗しました。ログイン画面から再試行してください。");
        if (string.IsNullOrWhiteSpace(volume)) return;
        // Volume creation requires the newly issued administrator JWT.
        EnsureCurrent(version + 1, ct);
        try { await volumes.CreateAsync(volume, username, password, encrypted: true, ct); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            throw new InvalidOperationException("管理者を作成してログイン済みです。ボリューム作成に失敗しました。ボリューム画面から再試行してください。", ex);
        }
        EnsureCurrent(version + 1, ct);
    }
}
