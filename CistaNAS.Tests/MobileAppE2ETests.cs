using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Abstractions;
using CistaNAS.Mobile.Core.Services;
using CistaNAS.Mobile.Core.ViewModels;

namespace CistaNAS.Tests;

#region テスト用フェイク (プラットフォーム実装の代替)

/// <summary>メモリ内 IAppSettings。</summary>
internal sealed class MemoryAppSettings : IAppSettings
{
    public string? ServerUrl { get; set; }
    public string? Username { get; set; }
    public int SaveCount { get; private set; }
    public void Save() => SaveCount++;
}

/// <summary>メモリ内 ISecureKeyStore (ECDH 秘密鍵の保存先)。</summary>
internal sealed class MemorySecureKeyStore : ISecureKeyStore
{
    private readonly ConcurrentDictionary<string, byte[]> _store = new();
    public byte[]? Load(string name) => _store.TryGetValue(name, out var v) ? v : null;
    public void Save(string name, byte[] plaintext) => _store[name] = plaintext;
    public void Delete(string name) => _store.TryRemove(name, out _);
    public bool Exists(string name) => _store.ContainsKey(name);
}

/// <summary>テスト用一時ディレクトリの IFileCacheProvider。</summary>
internal sealed class TempFileCacheProvider : IFileCacheProvider
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"cista-mobile-cache-{Guid.NewGuid():N}");
    public Stream OpenWrite(string fileName)
    {
        Directory.CreateDirectory(_dir);
        return File.OpenWrite(Path.Combine(_dir, fileName));
    }
    public string GetPath(string fileName) => Path.Combine(_dir, fileName);
    public void Clear()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, true);
    }
}

/// <summary>起動記録を残す IExternalViewerLauncher (実際には起動しない)。</summary>
internal sealed class RecordingExternalViewer : IExternalViewerLauncher
{
    public List<(string FilePath, string MimeType)> Launched { get; } = [];
    public Task<bool> LaunchAsync(string filePath, string mimeType)
    {
        Launched.Add((filePath, mimeType));
        return Task.FromResult(true);
    }
}

#endregion

/// <summary>
/// モバイルアプリ (CistaNAS.Mobile.Core) の Aspire E2E テスト。
/// 実際の CistaNAS.Web に対し、Android アプリと同一の ViewModel / サービス群を駆動して
/// オンボーディング → ログイン → ボリューム作成 → マウント → 転送 → 閲覧までを検証する。
/// </summary>
[Collection("Aspire")]
public class MobileAppE2ETests(AspireFixture fixture)
{
    private const string VolumePassword = "mobile-pw-1234";

    /// <summary>テスト用 AppServices を構築し、Aspire の webfrontend へ接続済みにする。</summary>
    private AppServices CreateApp()
    {
        // Aspire の開発証明書は信頼されていないため検証をバイパス
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        var app = new AppServices(
            new MemorySecureKeyStore(), new MemoryAppSettings(),
            new TempFileCacheProvider(), new RecordingExternalViewer(), handler);
        app.Session.ConfigureServer(fixture.Http.BaseAddress!.ToString());
        return app;
    }

    /// <summary>RunBusyAsync は async void からも同期開始されるため、IsBusy が下がるまで待てばよい。</summary>
    private static async Task WaitIdleAsync(BusyViewModelBase vm, string context, int timeoutMs = 30_000)
    {
        var sw = Stopwatch.StartNew();
        while (vm.IsBusy)
        {
            if (sw.ElapsedMilliseconds > timeoutMs)
                Assert.Fail($"{context}: {timeoutMs}ms 以内に完了しませんでした。Error={vm.Error}");
            await Task.Delay(50);
        }
        Assert.Null(vm.Error);
    }

    /// <summary>前画面へ戻り、戻り先の OnNavigatedTo 自動再ロードの完了を待つ。</summary>
    private static async Task<T> GoBackAsync<T>(AppServices app, string context) where T : BusyViewModelBase
    {
        Assert.True(app.Navigation.GoBack());
        var vm = Assert.IsAssignableFrom<T>(app.Navigation.Current);
        await WaitIdleAsync(vm, context);
        return vm;
    }

    /// <summary>Connect → Login までを実行し、VolumesViewModel へ遷移させる。</summary>
    private async Task<VolumesViewModel> LoginAsync(AppServices app)
    {
        var connect = new ConnectViewModel(app) { ServerUrl = fixture.Http.BaseAddress!.ToString() };
        app.Navigation.NavigateTo(connect);
        await connect.ConnectCommand.ExecuteAsync(null);
        Assert.Null(connect.Error);
        var login = Assert.IsAssignableFrom<LoginViewModel>(app.Navigation.Current);

        login.Username = AspireFixture.Username;
        login.Password = AspireFixture.Password;
        await login.LoginCommand.ExecuteAsync(null);
        Assert.Null(login.Error);

        var volumes = Assert.IsAssignableFrom<VolumesViewModel>(app.Navigation.Current);
        await WaitIdleAsync(volumes, "ボリューム一覧の初回ロード");
        return volumes;
    }

    [Fact]
    public async Task Onboarding_E2eeVolume_FullFlow()
    {
        using AppServices app = CreateApp();

        // --- オンボーディング: 接続 → ログイン ---
        VolumesViewModel volumes = await LoginAsync(app);
        Assert.Equal(AspireFixture.Username, app.Settings.Username);

        // --- E2EE ボリューム作成 ---
        volumes.CreateVolumeCommand.Execute(null);
        var create = Assert.IsAssignableFrom<CreateVolumeViewModel>(app.Navigation.Current);
        string volName = $"m-e2ee-{Guid.NewGuid():N}";
        create.VolumeName = volName;
        create.Password = VolumePassword;
        create.PasswordConfirm = VolumePassword;
        create.IsE2ee = true;
        await create.CreateCommand.ExecuteAsync(null);
        Assert.Null(create.Error);
        Assert.IsAssignableFrom<VolumesViewModel>(app.Navigation.Current); // 作成後は一覧へ戻る

        // --- 一覧に現れることを確認 (GoBack で開始された自動再ロードの完了を待ってから再読込) ---
        await WaitIdleAsync(volumes, "一覧の自動再ロード");
        await volumes.RefreshCommand.ExecuteAsync(null);
        await WaitIdleAsync(volumes, "一覧の再読込");
        VolumeListItem created = Assert.Single(volumes.Volumes, v => v.Name == volName);
        Assert.Equal("e2ee", created.EncryptionMode, ignoreCase: true);

        // --- マウント (wrapped key をローカルでアンラップ) ---
        volumes.OpenVolumeCommand.Execute(created);
        Assert.True(volumes.IsMountPromptVisible, "E2EE ボリュームは初回マウント時パスワード入力を求める");
        volumes.MountPassword = VolumePassword;
        await volumes.ConfirmMountCommand.ExecuteAsync(null);
        Assert.Null(volumes.Error);
        var browser = Assert.IsAssignableFrom<FileBrowserViewModel>(app.Navigation.Current);
        Assert.True(browser.IsE2ee);
        await WaitIdleAsync(browser, "ブラウザ初回ロード");

        // --- 画像ファイルをアップロード (チャンク分割されるサイズ) ---
        byte[] imageBytes = RandomNumberGenerator.GetBytes(1_500_000); // 既定チャンク 1MB → 2 チャンク
        using (var ms = new MemoryStream(imageBytes))
        {
            (string fileId, int chunkCount) = await app.Transfer.UploadAsync(volName, "photo.png", ms, imageBytes.Length);
            Assert.Equal(2, chunkCount);
            Assert.False(string.IsNullOrEmpty(fileId));
        }

        // --- 一覧に復号した名前で表示される ---
        await browser.RefreshCommand.ExecuteAsync(null);
        Assert.Null(browser.Error);
        FileItem item = Assert.Single(browser.Items, i => !i.IsFolder);
        Assert.Equal("photo.png", item.Name);
        Assert.Equal(FileCategory.Image, item.Category);

        // --- 画像ビューアで復号表示 ---
        browser.OpenItemCommand.Execute(item);
        var viewer = Assert.IsAssignableFrom<ImageViewerViewModel>(app.Navigation.Current);
        await WaitIdleAsync(viewer, "画像の復号");
        Assert.Equal(imageBytes, viewer.ImageData);

        // --- テキストファイルもアプリ内表示できる ---
        const string textContent = "モバイル E2E テスト — 日本語テキスト\n2 行目";
        byte[] textBytes = Encoding.UTF8.GetBytes(textContent);
        using (var ms = new MemoryStream(textBytes))
            await app.Transfer.UploadAsync(volName, "ノート.txt", ms, textBytes.Length);
        Assert.True(app.Navigation.GoBack()); // 画像ビューア → ブラウザ
        await WaitIdleAsync(browser, "ブラウザの自動再ロード");
        await browser.RefreshCommand.ExecuteAsync(null);
        await WaitIdleAsync(browser, "一覧の再読込");
        FileItem textItem = Assert.Single(browser.Items, i => i.Name == "ノート.txt");
        browser.OpenItemCommand.Execute(textItem);
        var textViewer = Assert.IsAssignableFrom<TextViewerViewModel>(app.Navigation.Current);
        await WaitIdleAsync(textViewer, "テキストの復号");
        Assert.Equal(textContent, textViewer.Content);

        // --- 動画は外部アプリ委譲 (キャッシュ復号 + ランチャー起動) ---
        byte[] videoBytes = RandomNumberGenerator.GetBytes(200_000);
        using (var ms = new MemoryStream(videoBytes))
            await app.Transfer.UploadAsync(volName, "clip.mp4", ms, videoBytes.Length);
        Assert.True(app.Navigation.GoBack());
        await WaitIdleAsync(browser, "ブラウザの自動再ロード");
        await browser.RefreshCommand.ExecuteAsync(null);
        await WaitIdleAsync(browser, "一覧の再読込");
        FileItem videoItem = Assert.Single(browser.Items, i => i.Name == "clip.mp4");
        browser.OpenItemCommand.Execute(videoItem);
        var external = Assert.IsAssignableFrom<ExternalViewerViewModel>(app.Navigation.Current);
        await WaitIdleAsync(external, "動画の復号と委譲");
        var launched = Assert.Single(((RecordingExternalViewer)app.ExternalViewer).Launched);
        Assert.Equal("video/mp4", launched.MimeType);
        Assert.True(File.Exists(launched.FilePath), "外部委譲先のキャッシュファイルが存在する");
        Assert.Equal(videoBytes, await File.ReadAllBytesAsync(launched.FilePath));
    }

    [Fact]
    public async Task ServerEncryptedVolume_FolderTree_BrowseAndDownload()
    {
        using AppServices app = CreateApp();
        VolumesViewModel volumes = await LoginAsync(app);

        // --- サーバー側暗号化ボリューム作成 ---
        volumes.CreateVolumeCommand.Execute(null);
        var create = (CreateVolumeViewModel)app.Navigation.Current!;
        string volName = $"m-server-{Guid.NewGuid():N}";
        create.VolumeName = volName;
        create.Password = VolumePassword;
        create.PasswordConfirm = VolumePassword;
        create.IsE2ee = false;
        await create.CreateCommand.ExecuteAsync(null);
        Assert.Null(create.Error);

        await WaitIdleAsync(volumes, "一覧の自動再ロード");
        await volumes.RefreshCommand.ExecuteAsync(null);
        await WaitIdleAsync(volumes, "一覧の再読込");
        VolumeListItem created = Assert.Single(volumes.Volumes, v => v.Name == volName);

        // --- パスワードでマウント (作成直後はサーバーが自動マウント済みなのでプロンプトは出ないこともある) ---
        volumes.OpenVolumeCommand.Execute(created);
        if (volumes.IsMountPromptVisible)
        {
            volumes.MountPassword = VolumePassword;
            await volumes.ConfirmMountCommand.ExecuteAsync(null);
            Assert.Null(volumes.Error);
        }
        var browser = Assert.IsAssignableFrom<FileBrowserViewModel>(app.Navigation.Current);
        Assert.False(browser.IsE2ee);
        await WaitIdleAsync(browser, "ブラウザ初回ロード");

        // --- サーバー API でフォルダ付きファイルをアップロード ---
        byte[] mdBytes = Encoding.UTF8.GetBytes("# サーバー暗号化ボリューム\n中身です。");
        byte[] pngBytes = RandomNumberGenerator.GetBytes(3000);
        await CistaNasApiClientFiles.UploadFileAsync(app.Session.Api, volName, "docs/readme.md", mdBytes);
        await CistaNasApiClientFiles.UploadFileAsync(app.Session.Api, volName, "pics/icon.png", pngBytes);

        await browser.RefreshCommand.ExecuteAsync(null);
        Assert.Null(browser.Error);
        Assert.Equal(2, browser.Items.Count);
        Assert.All(browser.Items, i => Assert.True(i.IsFolder));
        Assert.Equal(new[] { "docs", "pics" }, browser.Items.Select(i => i.Name).OrderBy(n => n));

        // --- フォルダ移動 → ファイル表示 ---
        browser.OpenItemCommand.Execute(browser.Items.Single(i => i.Name == "docs"));
        Assert.Equal("docs", browser.CurrentPath);
        FileItem md = Assert.Single(browser.Items, i => i.Name == "readme.md");

        // --- テキストビューア ---
        browser.OpenItemCommand.Execute(md);
        var textViewer = Assert.IsAssignableFrom<TextViewerViewModel>(app.Navigation.Current);
        await WaitIdleAsync(textViewer, "テキストのダウンロード");
        Assert.Equal(Encoding.UTF8.GetString(mdBytes), textViewer.Content);

        // --- 戻って別フォルダの画像 ---
        Assert.True(app.Navigation.GoBack());
        Assert.Equal("docs", browser.CurrentPath);
        browser.GoUpCommand.Execute(null);
        Assert.Equal("", browser.CurrentPath);
        browser.OpenItemCommand.Execute(browser.Items.Single(i => i.Name == "pics"));
        browser.OpenItemCommand.Execute(browser.Items.Single(i => i.Name == "icon.png"));
        var viewer = Assert.IsAssignableFrom<ImageViewerViewModel>(app.Navigation.Current);
        await WaitIdleAsync(viewer, "画像のダウンロード");
        Assert.Equal(pngBytes, viewer.ImageData);
    }

    [Fact]
    public async Task ExpiredToken_RaisesSessionExpired()
    {
        using AppServices app = CreateApp();

        string token = await app.Session.Api.LoginAsync(AspireFixture.Username, AspireFixture.Password);
        app.Session.SetToken(token);

        bool expired = false;
        app.SessionExpired += () => expired = true;

        // 無効トークンへ差し替えて API 呼び出し → 401 検知
        app.Session.SetToken("invalid-expired-token");
        await Assert.ThrowsAsync<HttpRequestException>(() => app.Session.Api.ListVolumesAsync());

        Assert.True(expired, "401 で SessionExpired が発火するはずです (UI はログイン画面へ戻す)。");
    }

    [Fact]
    public async Task Logout_ClearsTokenAndReturnsToLogin()
    {
        using AppServices app = CreateApp();
        VolumesViewModel volumes = await LoginAsync(app);

        volumes.LogoutCommand.Execute(null);

        Assert.IsAssignableFrom<LoginViewModel>(app.Navigation.Current); // ログアウト後はログイン画面へ戻る
        // トークンが破棄されたため、以降の API 呼び出しは 401 になる
        await Assert.ThrowsAsync<HttpRequestException>(() => app.Session.Api.ListVolumesAsync());
    }
}
