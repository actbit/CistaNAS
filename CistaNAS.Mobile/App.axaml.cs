using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using CistaNAS.Mobile.Core.Services;
using CistaNAS.Mobile.Core.ViewModels;
using CistaNAS.Mobile.Platform;
using CistaNAS.Mobile.Views;

namespace CistaNAS.Mobile;

// Android の暗黙的グローバル using により Android.App.Application と衝突するため完全修飾
public class App : Avalonia.Application
{
    public static AppServices? Services { get; private set; }

    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        Services ??= new AppServices(
            new AndroidSecureKeyStore(),
            new AndroidAppSettings(),
            new AndroidFileCacheProvider(),
            new AndroidExternalViewerLauncher());

        if (ApplicationLifetime is ISingleViewApplicationLifetime single)
        {
            var shell = new ShellViewModel(Services.Navigation);
            single.MainView = new ShellView { DataContext = shell };

            // 401 検知 → ログイン画面へ戻す
            Services.SessionExpired += () =>
            {
                Services.Session.ClearToken();
                Services.E2ee.ClearKeys();
                Services.Navigation.NavigateToRoot(new LoginViewModel(Services));
            };

            // 初期画面: サーバー URL 入力 (設定済みならプリフィル)
            Services.Navigation.NavigateTo(new ConnectViewModel(Services));
        }

        base.OnFrameworkInitializationCompleted();
    }
}
