using Aspire.Hosting.ApplicationModel;
using Aspire.Hosting.Testing;
using Microsoft.Playwright;

namespace CistaNAS.PlaywrightTests;

[Collection("Playwright")]
public sealed class InitialSetupBrowserTests(PlaywrightWebAppFixture fixture)
{
    [Fact]
    public async Task FreshInstallation_SetupCreatesTheRequestedEncryptedVolume()
    {
        string dataRoot = Path.Combine(Path.GetTempPath(), $"cista-pw-setup-{Guid.NewGuid():N}");
        try
        {
            var builder = await DistributedApplicationTestingBuilder.CreateAsync<Projects.CistaNAS_AppHost>();
            var project = builder.Resources.OfType<ProjectResource>().First(r => r.Name == "webfrontend");
            builder.CreateResourceBuilder(project).WithEnvironment("CistaNas__DataRoot", dataRoot);
            await using var app = await builder.BuildAsync();
            await app.StartAsync();
            string url = app.GetEndpoint("webfrontend", "https").ToString().TrimEnd('/');
            await using var context = await fixture.CreateAnonymousContextAsync();
            var page = await context.NewPageAsync();
            await page.GotoAsync(url + "/setup");
            await page.WaitForFunctionAsync("() => document.querySelector('form') !== null",
                options: new() { Timeout = 60000 });
            var inputs = page.Locator("form input");
            await inputs.Nth(0).FillAsync("admin");
            await inputs.Nth(0).PressAsync("Tab");
            await page.Locator("form input[type=password]").Nth(0).FillAsync(PlaywrightWebAppFixture.Password);
            await page.Locator("form input[type=password]").Nth(0).PressAsync("Tab");
            await page.Locator("form input[type=password]").Nth(1).FillAsync(PlaywrightWebAppFixture.Password);
            await page.Locator("form input[type=password]").Nth(1).PressAsync("Tab");
            Assert.True(await page.Locator("#chkVol").IsCheckedAsync());
            await page.GetByRole(AriaRole.Button, new() { Name = "セットアップ完了" }).ClickAsync();
            await page.WaitForURLAsync("**/volumes", new() { Timeout = 60000 });
            await page.WaitForFunctionAsync("() => !!document.querySelector('table') && document.querySelector('table').textContent.includes('data')");
            bool encrypted = await page.EvaluateAsync<bool>("""
                async () => {
                    const response = await fetch('/api/v1/volumes', {
                        headers: { Authorization: 'Bearer ' + sessionStorage.getItem('cista_jwt') }
                    });
                    if (!response.ok) throw new Error('list failed: ' + response.status);
                    const volumes = await response.json();
                    return volumes.some(v => v.name === 'data' && v.encrypted === true);
                }
                """);
            Assert.True(encrypted);
        }
        finally
        {
            if (Directory.Exists(dataRoot) && Path.GetFullPath(dataRoot).StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase))
            {
                // Aspire can return before the web process releases its SQLite
                // handles. Do not mask a browser assertion with teardown I/O.
                for (int attempt = 0; attempt < 6; attempt++)
                {
                    try { Directory.Delete(dataRoot, true); break; }
                    catch (IOException) when (attempt < 5) { await Task.Delay(250); }
                    catch (IOException) { break; }
                }
            }
        }
    }
}
