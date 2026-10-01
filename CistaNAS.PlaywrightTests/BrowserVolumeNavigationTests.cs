using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Playwright;

namespace CistaNAS.PlaywrightTests;

public partial class E2eeBrowserTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NavigatingBetweenFilePages_ReplacesPreviousVolumeState(bool encryptedFirst)
    {
        string first = encryptedFirst ? await CreateE2eeVolumeAsync() : await CreatePlainVolumeAsync();
        string second = await CreatePlainVolumeAsync();
        if (!encryptedFirst)
        {
            using var request = Authorized(HttpMethod.Post, $"/api/v1/files/{first}/first-secret.txt");
            request.Content = new ByteArrayContent(new byte[] { 42 });
            using var response = await fixture.Http.SendAsync(request);
            response.EnsureSuccessStatusCode();
        }
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();
        await page.GotoAsync($"{fixture.BaseUrl}/files/{first}");
        if (encryptedFirst) await UnlockPageAsync(page);
        else await page.GetByText("first-secret.txt", new() { Exact = true }).WaitForAsync();
        await NavigateInSameInstanceAsync(page, $"/files/{second}");
        await page.GetByRole(AriaRole.Heading, new() { Name = second, Exact = true }).WaitForAsync();
        await page.WaitForFunctionAsync("() => !document.body.textContent.includes('読み込み中...')");
        string body = await page.Locator("body").InnerTextAsync();
        Assert.DoesNotContain("first-secret.txt", body);
        Assert.DoesNotContain("クライアント側暗号化有効", body);
        Assert.True(await page.Locator("input[type=file]").IsVisibleAsync());
    }

    [Fact]
    public async Task ReturningToCustomChunkVolume_CanUploadAcrossItsChunkBoundary()
    {
        string volume = await CreateE2eeVolumeAsync(65536);
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();
        await page.GotoAsync($"{fixture.BaseUrl}/files/{volume}");
        await UnlockPageAsync(page);
        await page.GetByRole(AriaRole.Link, new() { Name = "ボリューム一覧に戻る", Exact = true }).ClickAsync();
        await page.WaitForURLAsync("**/volumes");
        await page.Locator("tr").Filter(new() { HasText = volume })
            .GetByRole(AriaRole.Link, new() { Name = "ファイル", Exact = true }).ClickAsync();
        await page.Locator("input[type=file]").WaitForAsync();
        await page.SetInputFilesAsync("input[type=file]", new FilePayload
            { Name = "custom-boundary.bin", MimeType = "application/octet-stream", Buffer = new byte[65537] });
        await page.WaitForFunctionAsync("() => !document.body.textContent.includes('アップロード中...')");
        await page.WaitForFunctionAsync("() => document.body.textContent.includes('custom-boundary.bin') || document.querySelector('.alert-danger')");
        Assert.Contains("custom-boundary.bin", await page.Locator("body").InnerTextAsync());
        using var request = Authorized(HttpMethod.Get, $"/api/v1/e2ee/{volume}/files");
        using var response = await fixture.Http.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var catalog = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(2, catalog.GetProperty("files")[0].GetProperty("chunkCount").GetInt32());
    }

    private async Task<string> CreatePlainVolumeAsync()
    {
        string volume = "pw-plain-" + Guid.NewGuid().ToString("N");
        using var request = Authorized(HttpMethod.Post, "/api/v1/volumes");
        request.Content = JsonContent.Create(new { name = volume, username = PlaywrightWebAppFixture.Username, password = (string?)null, encrypted = false });
        using var response = await fixture.Http.SendAsync(request);
        response.EnsureSuccessStatusCode();
        return volume;
    }
    private HttpRequestMessage Authorized(HttpMethod method, string path)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", fixture.Token);
        return request;
    }
    private static async Task UnlockPageAsync(IPage page)
    {
        await page.Locator("input[type=password]").FillAsync(PlaywrightWebAppFixture.Password);
        await page.Locator("input[type=password]").PressAsync("Tab");
        await page.GetByRole(AriaRole.Button, new() { Name = "ロック解除", Exact = true }).ClickAsync();
        await page.WaitForFunctionAsync("() => document.body.textContent.includes('クライアント側暗号化有効')");
    }
    private static Task NavigateInSameInstanceAsync(IPage page, string path) => page.EvaluateAsync("""
        path => { const link = document.createElement('a'); link.href = path; document.body.appendChild(link); link.click(); link.remove(); }
        """, path);
}
