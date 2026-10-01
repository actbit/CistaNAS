using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>ログイン画面。</summary>
public sealed partial class LoginViewModel(AppServices app) : SessionViewModelBase
{
    [ObservableProperty]
    private string _username = app.Settings.Username ?? "";

    [ObservableProperty]
    private string _password = "";

    public override string Title => "ログイン";

    [RelayCommand]
    private Task LoginAsync(CancellationToken ct) => RunSessionBusyAsync(async () =>
    {
        if (string.IsNullOrWhiteSpace(Username)) throw new InvalidOperationException("ユーザー名を入力してください。");
        string username = Username, password = Password;
        using var operation = BeginOperation(app, ct);
        string token = await app.Session.Api.LoginAsync(username, password, operation.Cancellation);
        operation.CompleteLogin(token, username, () => app.Navigation.NavigateToRoot(new VolumesViewModel(app)));
    });

    public override void OnNavigatedFrom() { base.OnNavigatedFrom(); Password = ""; }

    protected override string FriendlyError(Exception ex) =>
        ex is HttpRequestException h && h.StatusCode == System.Net.HttpStatusCode.Unauthorized
            ? "ユーザー名またはパスワードが違います。"
            : ex.Message;
}
