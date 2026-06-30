using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Playwright;

namespace CistaNAS.PlaywrightTests;

/// <summary>
/// Aspire AppHost を1回だけ起動し、Playwright (Chromium) と認証済みブラウザコンテキストを提供する Fixture。
/// 既存の AspireFixture（CistaNAS.Tests）と同じ AppHost 起動パターンだが、internal で参照できないため再実装。
/// xUnit の ICollectionFixture でコレクション内の全テストクラスで共有。
/// </summary>
public sealed class PlaywrightWebAppFixture : IAsyncLifetime
{
    private DistributedApplication? _app;
    private string _tempDataRoot = "";
    private IPlaywright? _playwright;

    public HttpClient Http { get; private set; } = null!;
    public string Token { get; private set; } = "";
    public IBrowser Browser { get; private set; } = null!;
    public string BaseUrl { get; private set; } = "";

    public const string Username = "admin";
    public const string Password = "initial-pw-1234";

    public async Task InitializeAsync()
    {
        // テスト専用の一時ディレクトリ
        _tempDataRoot = Path.Combine(Path.GetTempPath(), $"cista-pw-{Guid.NewGuid():N}");

        var builder = await DistributedApplicationTestingBuilder.CreateAsync<Projects.CistaNAS_AppHost>();
        var proj = builder.Resources
            .OfType<ProjectResource>()
            .First(r => r.Name == "webfrontend");
        builder.CreateResourceBuilder(proj)
            .WithEnvironment("CistaNas__DataRoot", _tempDataRoot);

        _app = await builder.BuildAsync();
        await _app.StartAsync();

        // HTTPS エンドポイント（HTTP は HTTPS へリダイレクトされ Auth ヘッダーが剥がれる）
        var endpoint = _app.GetEndpoint("webfrontend", "https");
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
        };
        Http = new HttpClient(handler) { BaseAddress = endpoint };
        BaseUrl = endpoint.ToString().TrimEnd('/');

        // 初期管理者作成（既存なら 409 Conflict を許容）
        var setupResp = await Http.PostAsJsonAsync("/api/v1/auth/setup",
            new { username = Username, password = Password });
        Assert.True(setupResp.IsSuccessStatusCode || setupResp.StatusCode == HttpStatusCode.Conflict);

        // ログイン → JWT 取得
        var loginResp = await Http.PostAsJsonAsync("/api/v1/auth/login",
            new { username = Username, password = Password });
        Assert.True(loginResp.IsSuccessStatusCode,
            $"Login failed: {loginResp.StatusCode} - {await loginResp.Content.ReadAsStringAsync()}");
        var loginJson = await loginResp.Content.ReadFromJsonAsync<JsonElement>();
        Token = loginJson.GetProperty("accessToken").GetString()!;

        // Playwright / Chromium 起動（ヘッドレス）
        // --disable-popup-blocking: Blazor の JS interop 経由の window.open(<a click>) が
        // ユーザー操作文脈を失って popup blocker にブロックされるのを防ぐ（FileDownloadTests 用）
        _playwright = await Playwright.CreateAsync();
        Browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
        {
            Headless = true,
            Args = new[] { "--disable-popup-blocking" },
        });
    }

    /// <summary>
    /// 認証済みブラウザコンテキストを作成。
    /// 各ページロード前に sessionStorage へ JWT を注入し、WASM の WasmAuthStateProvider.TryRestoreAsync で
    /// 自動ログイン復元させる（ログイン画面操作を省略）。
    /// </summary>
    public async Task<IBrowserContext> CreateAuthenticatedContextAsync()
    {
        var context = await Browser.NewContextAsync(new BrowserNewContextOptions
        {
            IgnoreHTTPSErrors = true,
        });

        // 自己署名証明書の HTTPS を許可
        var tokenJson = JsonSerializer.Serialize(Token);
        // 有効期限内の expires を設定（AccessTokenMinutes=30 に対し余裕を持って 25 分後）
        var expires = DateTimeOffset.UtcNow.AddMinutes(25).ToString("O");
        var expiresJson = JsonSerializer.Serialize(expires);

        await context.AddInitScriptAsync($$"""
            try {
              sessionStorage.setItem('cista_jwt', {{tokenJson}});
              sessionStorage.setItem('cista_jwt_expires', {{expiresJson}});
            } catch (e) { /* sessionStorage 未利用時は無視 */ }
        """);

        return context;
    }

    /// <summary>未認証ブラウザコンテキスト（認証ガードのテスト用）。</summary>
    public Task<IBrowserContext> CreateAnonymousContextAsync()
        => Browser.NewContextAsync(new BrowserNewContextOptions { IgnoreHTTPSErrors = true });

    public async Task DisposeAsync()
    {
        if (Browser is not null) await Browser.CloseAsync();
        _playwright?.Dispose();
        Http?.Dispose();
        if (_app is not null) await _app.DisposeAsync();

        if (Directory.Exists(_tempDataRoot))
        {
            try { Directory.Delete(_tempDataRoot, true); }
            catch (IOException) { /* ベストエフォート */ }
        }
    }

    async Task IAsyncLifetime.DisposeAsync() => await DisposeAsync();
}

/// <summary>テストコレクション定義。PlaywrightWebAppFixture を1回だけ生成し共有。</summary>
[CollectionDefinition("Playwright")]
public class PlaywrightCollection : ICollectionFixture<PlaywrightWebAppFixture>;
