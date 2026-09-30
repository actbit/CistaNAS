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
        DeleteLegacyViewerCache();
        Services ??= new AppServices(
            new AndroidSecureKeyStore(),
            new AndroidAppSettings(),
            new AndroidFileViewerLauncher());

        if (ApplicationLifetime is ISingleViewApplicationLifetime single)
        {
            var shell = new ShellViewModel(Services.Navigation);
            single.MainView = new ShellView { DataContext = shell };

            // 401 検知 → ログイン画面へ戻す
            Services.SessionExpired += () =>
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                    Services.Navigation.NavigateToRoot(new LoginViewModel(Services)));
            };

            // 初期画面: サーバー URL 入力 (設定済みならプリフィル)
            Services.Navigation.NavigateTo(new ConnectViewModel(Services));
        }

        base.OnFrameworkInitializationCompleted();
    }

    private static void DeleteLegacyViewerCache()
    {
        // 旧版で生成された復号ファイルだけを削除し、新しいキャッシュは作らない。
        string directory = Path.Combine(Android.App.Application.Context.CacheDir!.Path!, "externalviewer");
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
