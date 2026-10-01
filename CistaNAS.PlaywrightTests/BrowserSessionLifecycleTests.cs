using Microsoft.Playwright;

namespace CistaNAS.PlaywrightTests;

public partial class E2eeBrowserTests
{
    [Fact]
    public async Task LogoutAndLoginInTheSameTab_RequiresUnlockingTheE2eeVolumeAgain()
    {
        string volume = await CreateE2eeVolumeAsync();
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();
        await page.GotoAsync($"{fixture.BaseUrl}/files/{volume}");
        await page.WaitForFunctionAsync("() => document.querySelector('input[type=password]') !== null",
            options: new PageWaitForFunctionOptions { Timeout = 60000 });
        await page.Locator("input[type=password]").FillAsync(PlaywrightWebAppFixture.Password);
        await page.Locator("input[type=password]").PressAsync("Tab");
        await page.GetByRole(AriaRole.Button, new() { Name = "ロック解除", Exact = true }).ClickAsync();
        await page.WaitForFunctionAsync("() => document.body.textContent.includes('クライアント側暗号化有効')");

        await page.GetByRole(AriaRole.Button, new() { Name = "ログアウト", Exact = true }).ClickAsync();
        await page.Locator(".sidebar").GetByRole(AriaRole.Link, new() { Name = "ログイン" }).ClickAsync();
        await page.WaitForURLAsync("**/login");
        await page.Locator("form input").Nth(0).FillAsync(PlaywrightWebAppFixture.Username);
        await page.Locator("form input").Nth(0).PressAsync("Tab");
        await page.Locator("form input[type=password]").FillAsync(PlaywrightWebAppFixture.Password);
        await page.Locator("form input[type=password]").PressAsync("Tab");
        await page.GetByRole(AriaRole.Button, new() { Name = "ログイン", Exact = true }).ClickAsync();
        await page.WaitForURLAsync("**/volumes");

        // Preserve this WASM instance so a full reload cannot hide retained keys.
        await page.EvaluateAsync("""
            path => {
                const link = document.createElement('a');
                link.href = path;
                document.body.appendChild(link);
                link.click();
                link.remove();
            }
            """, $"/files/{volume}");
        await page.WaitForFunctionAsync("() => document.querySelector('input[type=password]') !== null");
        Assert.True(await page.GetByRole(AriaRole.Button, new() { Name = "ロック解除", Exact = true }).IsVisibleAsync());
        Assert.DoesNotContain("クライアント側暗号化有効", await page.Locator("body").InnerTextAsync());
    }
}
