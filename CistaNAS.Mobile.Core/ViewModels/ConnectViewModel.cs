using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>サーバー URL 入力画面 (オンボーディングの起点)。</summary>
public sealed partial class ConnectViewModel(AppServices app) : SessionViewModelBase
{
    [ObservableProperty]
    private string _serverUrl = app.Settings.ServerUrl ?? "";

    public override string Title => "サーバーに接続";

    [RelayCommand]
    private Task ConnectAsync(CancellationToken ct) => RunSessionBusyAsync(async () =>
    {
        app.ClearSession();
        string server = ServerUrl.TrimEnd('/');
        app.Session.ConfigureServer(server);
        using var operation = BeginOperation(app, ct);
        bool hasUsers = await app.Session.Api.HasUsersAsync(operation.Cancellation);
        operation.Commit(() =>
        {
            app.Settings.ServerUrl = server;
            app.Settings.Save();
            app.Navigation.NavigateTo(hasUsers ? new LoginViewModel(app) : new SetupViewModel(app));
        });
    });

    protected override string FriendlyError(Exception ex) =>
        ex is HttpRequestException ? "サーバーに接続できません。URL とネットワークを確認してください。" : ex.Message;
}
