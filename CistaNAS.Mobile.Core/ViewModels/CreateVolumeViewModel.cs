using System.Security.Cryptography;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>ボリューム新規作成 (server / e2ee 両モード)。</summary>
public sealed partial class CreateVolumeViewModel(AppServices app) : SessionViewModelBase
{
    [ObservableProperty]
    private string _volumeName = "";

    [ObservableProperty]
    private string _password = "";

    [ObservableProperty]
    private string _passwordConfirm = "";

    /// <summary>true = E2EE (クライアント暗号化) / false = サーバー側暗号化。</summary>
    [ObservableProperty]
    private bool _isE2ee = true;

    public override string Title => "ボリューム作成";

    [RelayCommand]
    private Task CreateAsync(CancellationToken ct) => RunSessionBusyAsync(async () =>
    {
        string username = app.Settings.Username ?? throw new InvalidOperationException("未ログインです。");
        if (string.IsNullOrWhiteSpace(VolumeName)) throw new InvalidOperationException("ボリューム名を入力してください。");
        if (Password.Length < 8) throw new InvalidOperationException("パスワードは 8 文字以上にしてください。");
        if (Password != PasswordConfirm) throw new InvalidOperationException("パスワードが一致しません。");

        string name = VolumeName, password = Password;
        bool e2ee = IsE2ee;
        using var operation = BeginOperation(app, ct);
        if (e2ee)
        {
            await CreateE2eeVolumeAsync(name, username, password, operation);
        }
        else
        {
            // インスタンス側 CreateVolumeAsync (E2EE 用) と同名のため拡張メソッドを明示呼び出し
            await CistaNasApiClientVolumes.CreateVolumeAsync(app.Session.Api, name, username, password, encrypted: true, operation.Cancellation);
        }
        operation.Commit(() => app.Navigation.GoBack());
    });

    public override void OnNavigatedFrom()
    {
        base.OnNavigatedFrom();
        Password = PasswordConfirm = "";
    }

    /// <summary>
    /// E2EE ボリューム作成: クライアントで masterKey を生成してパスワード由来の KEK でラップし、
    /// wrapped key のみをサーバーへ送る (Desktop Client / WASM と同一プロトコル)。
    /// </summary>
    private async Task CreateE2eeVolumeAsync(string name, string username, string password, ClientSessionOperation operation)
    {
        // サーバー設定の KDF 種別に従う（既定: Argon2id+PBKDF2 合成）
        KdfSpec spec = await GetCreationKdfAsync(operation.Cancellation);
        operation.EnsureCurrent();
        byte[] salt = RandomNumberGenerator.GetBytes(E2eeCrypto.SaltSize);
        byte[] kek = E2eeCrypto.DeriveKek(username, password, salt, spec);
        try
        {
            byte[] masterKey = E2eeCrypto.GenerateMasterKey();
            try
            {
                (byte[] nonce, byte[] ciphertext, byte[] tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
                operation.EnsureCurrent();
                await app.Session.Api.CreateVolumeAsync(name, username, nonce, ciphertext, tag, salt, ToKdfInfo(spec), ct: operation.Cancellation);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(masterKey);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>
    /// 新規 E2EE ボリュームの KEK 導出に使う KDF スペックをサーバー設定から取得する
    /// （Argon2id+PBKDF2 合成 or Argon2id 単独）。取得失敗時は現行標準にフォールバック。
    /// </summary>
    private async Task<KdfSpec> GetCreationKdfAsync(CancellationToken ct)
    {
        try
        {
            var settings = await CistaNasApiClientSettings.GetEncryptionSettingsAsync(app.Session.Api, ct);
            return string.Equals(settings.KdfAlgorithm, KdfSpec.Argon2idRaw, StringComparison.Ordinal)
                ? new KdfSpec(KdfSpec.Argon2idRaw, 0, settings.KdfMemoryKiB, settings.KdfParallelism, settings.KdfTimeCost)
                : new KdfSpec(KdfSpec.Argon2id, settings.KdfIterations, settings.KdfMemoryKiB, settings.KdfParallelism, settings.KdfTimeCost);
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            return KdfSpec.DefaultArgon2id;
        }
    }

    private static KdfInfo ToKdfInfo(KdfSpec spec) =>
        new(spec.Algorithm, spec.Iterations, spec.MemoryKiB, spec.TimeCost, spec.Parallelism);
}
