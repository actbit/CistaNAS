using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>ログイン画面。</summary>
public sealed partial class LoginViewModel(AppServices app) : BusyViewModelBase
{
    [ObservableProperty]
    private string _username = app.Settings.Username ?? "";

    [ObservableProperty]
    private string _password = "";

    public override string Title => "ログイン";

    [RelayCommand]
    private Task LoginAsync(CancellationToken ct) => RunBusyAsync(async () =>
    {
        if (string.IsNullOrWhiteSpace(Username)) throw new InvalidOperationException("ユーザー名を入力してください。");
        string token = await app.Session.Api.LoginAsync(Username, Password);
        app.Session.SetToken(token);
        app.Settings.Username = Username;
        app.Settings.Save();
        app.Navigation.NavigateToRoot(new VolumesViewModel(app));
    });

    protected override string FriendlyError(Exception ex) =>
        ex is HttpRequestException h && h.StatusCode == System.Net.HttpStatusCode.Unauthorized
            ? "ユーザー名またはパスワードが違います。"
            : ex.Message;
}
