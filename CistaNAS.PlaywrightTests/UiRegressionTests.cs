using Microsoft.Playwright;

namespace CistaNAS.PlaywrightTests;

/// <summary>
/// WASM フロントエンドの UI 回帰テスト。
/// 各ページの表示・認証フロー（ログイン/ログアウト/認証ガード）を実ブラウザで検証する。
/// </summary>
[Collection("Playwright")]
public class UiRegressionTests(PlaywrightWebAppFixture fixture)
{
    private const int WasmLoadTimeout = 60000;

    private static Task WaitForWasmReady(IPage page, string jsPredicate) =>
        page.WaitForFunctionAsync(jsPredicate,
            options: new PageWaitForFunctionOptions { Timeout = WasmLoadTimeout });

    /// <summary>Home ページがタイトルを表示する。</summary>
    [Fact]
    public async Task HomePage_DisplaysTitle()
    {
        await using var context = await fixture.CreateAnonymousContextAsync();
        var page = await context.NewPageAsync();

        await page.GotoAsync(fixture.BaseUrl + "/");
        await WaitForWasmReady(page, "() => document.querySelector('h1') !== null");

        var h1 = await page.Locator("h1").First.InnerTextAsync();
        Assert.Contains("CistaNAS", h1);
    }

    /// <summary>ログインページがフォームとボタンを表示する。</summary>
    [Fact]
    public async Task LoginPage_RendersForm()
    {
        await using var context = await fixture.CreateAnonymousContextAsync();
        var page = await context.NewPageAsync();

        await page.GotoAsync(fixture.BaseUrl + "/login");
        await WaitForWasmReady(page, "() => document.querySelector('form') !== null");

        Assert.True(await page.Locator("input[type=password]").IsVisibleAsync());
        Assert.True(await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "ログイン" }).IsVisibleAsync());
    }

    /// <summary>ログイン画面操作で /volumes へ遷移し、NavMenu に「ログアウト」が表示される。</summary>
    [Fact]
    public async Task LoginFlow_NavigatesToVolumes()
    {
        await using var context = await fixture.CreateAnonymousContextAsync();
        var page = await context.NewPageAsync();

        await page.GotoAsync(fixture.BaseUrl + "/login");
        await WaitForWasmReady(page, "() => document.querySelector('form') !== null");

        // form 内の input で特定（NavMenu の navbar-toggler checkbox は form 外なので除外）
        var usernameInput = page.Locator("form input").Nth(0);
        var passwordInput = page.Locator("form input[type=password]");
        await usernameInput.FillAsync(PlaywrightWebAppFixture.Username);
        await usernameInput.PressAsync("Tab"); // change イベント発火で Blazor @bind に反映
        await passwordInput.FillAsync(PlaywrightWebAppFixture.Password);
        await passwordInput.PressAsync("Tab");

        // API 呼び出しを記録（デバッグ用）
        var apiCalls = new List<string>();
        page.Response += (_, r) =>
        {
            if (r.Url.Contains("/api/", StringComparison.OrdinalIgnoreCase))
                apiCalls.Add($"{r.Url} -> {(int)r.Status}");
        };
        var consoleErrors = new List<string>();
        page.Console += (_, msg) => { if (msg.Type == "error") consoleErrors.Add(msg.Text); };
        page.PageError += (_, err) => consoleErrors.Add($"PAGEERROR: {err}");

        await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "ログイン" }).ClickAsync();

        try
        {
            await page.WaitForURLAsync("**/volumes", new PageWaitForURLOptions { Timeout = 20000 });
        }
        catch (TimeoutException)
        {
            var alert = page.Locator(".alert-danger");
            var alertText = await alert.CountAsync() > 0 ? await alert.First.InnerTextAsync() : "(no alert)";
            Assert.Fail(
                $"ログインで /volumes へ遷移しませんでした。URL: {page.Url}" +
                $"\nアラート: {alertText}" +
                $"\nAPI 呼び出し: {(apiCalls.Count == 0 ? "(なし)" : string.Join(" | ", apiCalls))}" +
                $"\nコンソールエラー:\n  - {string.Join("\n  - ", consoleErrors)}");
        }

        // NavMenu に「ログアウト」ボタンが表示される（認証済み状態）
        await page.WaitForFunctionAsync(
            "() => !!document.querySelector('.sidebar') && document.querySelector('.sidebar').textContent.includes('ログアウト')",
            options: new PageWaitForFunctionOptions { Timeout = 15000 });
        Assert.Contains("ログアウト", await page.Locator(".sidebar").InnerTextAsync());
    }

    /// <summary>未認証で Files ページへアクセスすると「ログインしてください」警告が出る。</summary>
    [Fact]
    public async Task Unauthenticated_FilesPage_ShowsLoginPrompt()
    {
        await using var context = await fixture.CreateAnonymousContextAsync();
        var page = await context.NewPageAsync();

        await page.GotoAsync(fixture.BaseUrl + "/files/test-vol");
        await WaitForWasmReady(page, "() => document.querySelector('.alert-warning') !== null");

        var text = await page.Locator(".alert-warning").First.InnerTextAsync();
        Assert.Contains("ログイン", text);
    }

    /// <summary>ログアウト操作で認証状態が解除され、NavMenu に「ログイン」リンクが表示される。</summary>
    [Fact]
    public async Task LogoutFlow_ClearsAuthState()
    {
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();

        await page.GotoAsync(fixture.BaseUrl + "/volumes");
        await page.WaitForFunctionAsync(
            "() => !!document.querySelector('.sidebar') && document.querySelector('.sidebar').textContent.includes('ログアウト')",
            options: new PageWaitForFunctionOptions { Timeout = WasmLoadTimeout });

        await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "ログアウト" }).ClickAsync();

        // ログアウト後、NavMenu に「ログイン」リンクが表示される
        await page.WaitForFunctionAsync(
            "() => !!document.querySelector('.sidebar') && document.querySelector('.sidebar').textContent.includes('ログイン')",
            options: new PageWaitForFunctionOptions { Timeout = 15000 });
        var sidebar = await page.Locator(".sidebar").InnerTextAsync();
        Assert.Contains("ログイン", sidebar);
    }
}
