using Microsoft.Playwright;

namespace CistaNAS.PlaywrightTests;

/// <summary>
/// CSP（Content Security Policy）違反の自動検出テスト。
/// 実際の Chromium で WASM アプリをロードし、コンソールに出る CSP 違反（Refused to ...）
/// がゼロであることを検証する。.NET 10 WASM の import map 等が CSP に引っかからないかを自動検出。
/// </summary>
[Collection("Playwright")]
public class CspTests(PlaywrightWebAppFixture fixture)
{
    [Fact]
    public async Task WasmApp_Loads_WithoutCspViolations()
    {
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();

        var consoleErrors = new List<string>();
        page.Console += (_, msg) =>
        {
            if (msg.Type == "error")
                consoleErrors.Add(msg.Text);
        };
        page.PageError += (_, err) => consoleErrors.Add($"PAGEERROR: {err}");

        // WASM 初期化完了（#app 内に h1 が出現）を待つ。初回ロードは重いため長めのタイムアウト。
        await page.GotoAsync(fixture.BaseUrl + "/", new PageGotoOptions
        {
            WaitUntil = WaitUntilState.Load,
        });
        bool wasmLoaded;
        try
        {
            await page.WaitForFunctionAsync(
                "() => document.querySelector('#app h1') !== null",
                options: new PageWaitForFunctionOptions { Timeout = 90000 });
            wasmLoaded = true;
        }
        catch (TimeoutException)
        {
            // WASM ロード未完（CSP 違反でスクリプトがブロックされた可能性）。続行して違反を報告。
            wasmLoaded = false;
        }

        // 少し余裕を持たせて遅延違反を捕捉
        await page.WaitForTimeoutAsync(1000);

        // CSP 違反を抽出（"Content Security Policy" を含むエラーのみ。
        // "Refused to ..." だけだと bootstrap の MIME/404 エラー等の偽陽性を含むため CSP 明示で絞る）
        var violations = consoleErrors
            .Where(e => e.Contains("Content Security Policy", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (!wasmLoaded)
        {
            var content = await page.ContentAsync();
            var preview = content.Length > 800 ? content[..800] : content;
            Assert.Fail(
                $"WASM アプリが90秒以内にロードされませんでした（CSP 違反でブロックされた可能性）。" +
                $"\n#app 内容: {preview}" +
                $"\nコンソールエラー ({consoleErrors.Count} 件):\n  - {string.Join("\n  - ", consoleErrors)}");
        }

        Assert.Empty(violations);
    }
}
