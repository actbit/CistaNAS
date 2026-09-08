using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>サーバー URL 入力画面 (オンボーディングの起点)。</summary>
public sealed partial class ConnectViewModel(AppServices app) : BusyViewModelBase
{
    [ObservableProperty]
    private string _serverUrl = app.Settings.ServerUrl ?? "";

    public override string Title => "サーバーに接続";

    [RelayCommand]
    private Task ConnectAsync(CancellationToken ct) => RunBusyAsync(async () =>
    {
        app.Session.ConfigureServer(ServerUrl);
        bool hasUsers = await app.Session.Api.HasUsersAsync();
        app.Settings.ServerUrl = ServerUrl.TrimEnd('/');
        app.Settings.Save();
        app.Navigation.NavigateTo(hasUsers ? new LoginViewModel(app) : new SetupViewModel(app));
    });

    protected override string FriendlyError(Exception ex) =>
        ex is HttpRequestException ? "サーバーに接続できません。URL とネットワークを確認してください。" : ex.Message;
}
