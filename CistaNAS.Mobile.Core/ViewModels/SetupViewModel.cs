using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>初回オンボーディング: 管理者ユーザー作成 → ログイン。</summary>
public sealed partial class SetupViewModel(AppServices app) : BusyViewModelBase
{
    [ObservableProperty]
    private string _username = "";

    [ObservableProperty]
    private string _password = "";

    [ObservableProperty]
    private string _passwordConfirm = "";

    public override string Title => "初期セットアップ";

    [RelayCommand]
    private Task SetupAsync(CancellationToken ct) => RunBusyAsync(async () =>
    {
        if (string.IsNullOrWhiteSpace(Username)) throw new InvalidOperationException("ユーザー名を入力してください。");
        if (Password.Length < 8) throw new InvalidOperationException("パスワードは 8 文字以上にしてください。");
        if (Password != PasswordConfirm) throw new InvalidOperationException("パスワードが一致しません。");

        await app.Session.Api.RunInitialSetupAsync(Username, Password);
        await LoginAsync(ct);
    });

    private async Task LoginAsync(CancellationToken ct)
    {
        string token = await app.Session.Api.LoginAsync(Username, Password);
        app.Session.SetToken(token);
        app.Settings.Username = Username;
        app.Settings.Save();
        app.Navigation.NavigateToRoot(new VolumesViewModel(app));
    }
}
