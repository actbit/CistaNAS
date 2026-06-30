using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using CistaNAS.Wasm.Services;
using Microsoft.Playwright;

namespace CistaNAS.PlaywrightTests;

/// <summary>
/// 通常（非暗号化）ボリュームのダウンロードフローテスト。
/// Files.razor の DownloadFile が eval を使わず cista.openUrl（window.open）で
/// ストリーミング URL を開けること、CSP でブロックされないことを検証する。
/// （E2EE ダウンロードは E2eeBrowserTests がカバー。ここは通常ボリューム専用）
/// </summary>
[Collection("Playwright")]
public class FileDownloadTests(PlaywrightWebAppFixture fixture)
{
    /// <summary>API で通常ボリュームを作成してファイルを置き、ボリューム名を返す。</summary>
    private async Task<string> CreateNormalVolumeWithFileAsync(string fileName, string content)
    {
        string volName = $"pw-normal-{Guid.NewGuid():N}";

        using var createReq = new HttpRequestMessage(HttpMethod.Post, "/api/v1/volumes");
        createReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", fixture.Token);
        createReq.Content = JsonContent.Create(new
        {
            name = volName,
            username = PlaywrightWebAppFixture.Username,
            password = (string?)null,
            encrypted = false,
        });
        var createResp = await fixture.Http.SendAsync(createReq);
        Assert.True(createResp.IsSuccessStatusCode, $"create-volume failed: {createResp.StatusCode}");

        // ファイルアップロード
        using var uploadReq = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/files/{volName}/{fileName}");
        uploadReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", fixture.Token);
        uploadReq.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(content));
        uploadReq.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        var uploadResp = await fixture.Http.SendAsync(uploadReq);
        Assert.True(uploadResp.IsSuccessStatusCode, $"upload failed: {uploadResp.StatusCode}");

        return volName;
    }

    /// <summary>「DL」ボタンで window.open が起動し、ストリーミングトークン付き URL の popup が開くこと。</summary>
    [Fact]
    public async Task NormalVolume_DownloadButton_OpensStreamPopup()
    {
        const string fileName = "normal-dl-test.txt";
        string volName = await CreateNormalVolumeWithFileAsync(fileName, "hello normal download");

        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();

        await page.GotoAsync($"{fixture.BaseUrl}/files/{volName}");
        await page.WaitForFunctionAsync(
            $"() => document.body.textContent.includes('{fileName}')",
            options: new PageWaitForFunctionOptions { Timeout = 60000 });

        var apiCalls = new List<string>();
        page.Response += (_, r) =>
        {
            if (r.Url.Contains("/api/", StringComparison.OrdinalIgnoreCase))
                apiCalls.Add($"{r.Url.Replace(fixture.BaseUrl, "")} -> {(int)r.Status}");
        };
        var consoleErrors = new List<string>();
        page.Console += (_, msg) => { if (msg.Type == "error") consoleErrors.Add(msg.Text); };
        page.PageError += (_, err) => consoleErrors.Add($"PAGEERROR: {err}");
        IPage? popup = null;
        page.Popup += (_, p) => popup = p;

        // 「DL」クリック → cista.openUrl(url) → <a target=_blank> click で popup が開く
        await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "DL" }).First.ClickAsync();
        await page.WaitForTimeoutAsync(3000);

        // popup が開くこと（cista.openUrl が CSP でブロックされない = eval 修正の検証）
        Assert.NotNull(popup);

        // DownloadFile フローが動くこと: stream/token API が呼ばれる
        Assert.True(apiCalls.Any(c => c.Contains("/stream/token")),
            $"stream/token API が呼ばれていません。API 呼び出し: {string.Join(" | ", apiCalls)}");
        // CSP 違反（eval 等のブロック）がないこと
        Assert.Empty(consoleErrors.Where(e => e.Contains("Content Security Policy", StringComparison.OrdinalIgnoreCase)));

        // NOTE: popup.Url の stream URL 厳密確認は、Playwright が <a target=_blank rel=noopener> の
        // popup URL を同期的に取得できないため対象外。url 構築の正しさは GetDownloadUrl_ReturnsAbsoluteUrl
        // で検証、popup が開く = cista.openUrl が機能することを検証。
    }

    /// <summary>GetDownloadUrl が絶対 URL を返すこと（url 構築の単体確認）。</summary>
    [Fact]
    public void GetDownloadUrl_ReturnsAbsoluteUrl()
    {
        var http = new HttpClient { BaseAddress = new Uri("https://localhost:12345/") };
        var api = new FileApiClient(http);

        var url = api.GetDownloadUrl("vol", "file.txt", "tok");

        Assert.StartsWith("https://localhost:12345/", url);
        Assert.Contains("/api/v1/stream/vol/file.txt?token=tok", url);
    }
}
