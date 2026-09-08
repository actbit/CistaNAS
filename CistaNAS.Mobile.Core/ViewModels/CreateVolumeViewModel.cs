using System.Security.Cryptography;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>ボリューム新規作成 (server / e2ee 両モード)。</summary>
public sealed partial class CreateVolumeViewModel(AppServices app) : BusyViewModelBase
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
    private Task CreateAsync(CancellationToken ct) => RunBusyAsync(async () =>
    {
        string username = app.Settings.Username ?? throw new InvalidOperationException("未ログインです。");
        if (string.IsNullOrWhiteSpace(VolumeName)) throw new InvalidOperationException("ボリューム名を入力してください。");
        if (Password.Length < 8) throw new InvalidOperationException("パスワードは 8 文字以上にしてください。");
        if (Password != PasswordConfirm) throw new InvalidOperationException("パスワードが一致しません。");

        if (IsE2ee)
        {
            await CreateE2eeVolumeAsync(username, Password);
        }
        else
        {
            // インスタンス側 CreateVolumeAsync (E2EE 用) と同名のため拡張メソッドを明示呼び出し
            await CistaNasApiClientVolumes.CreateVolumeAsync(app.Session.Api, VolumeName, username, Password, encrypted: true);
        }
        app.Navigation.GoBack();
    });

    /// <summary>
    /// E2EE ボリューム作成: クライアントで masterKey を生成してパスワード由来の KEK でラップし、
    /// wrapped key のみをサーバーへ送る (Desktop Client / WASM と同一プロトコル)。
    /// </summary>
    private async Task CreateE2eeVolumeAsync(string username, string password)
    {
        const int kdfIterations = 600_000;
        byte[] salt = RandomNumberGenerator.GetBytes(E2eeCrypto.SaltSize);
        byte[] kek = E2eeCrypto.DeriveKek(username, password, salt, kdfIterations);
        try
        {
            byte[] masterKey = E2eeCrypto.GenerateMasterKey();
            try
            {
                (byte[] nonce, byte[] ciphertext, byte[] tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
                await app.Session.Api.CreateVolumeAsync(VolumeName, username, nonce, ciphertext, tag, salt, kdfIterations);
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
}
