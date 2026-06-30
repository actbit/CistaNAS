using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;
using Microsoft.Playwright;

namespace CistaNAS.PlaywrightTests;

/// <summary>
/// 実ブラウザでの E2EE ラウンドトリップテスト。
/// 実際の JS（e2ee.js / Web Crypto API）で暗号化し、サーバー（C# E2eeCrypto）と互換かを実証する。
/// ハッピーパス（ボリューム作成 UI は複雑なため API で事前作成）→ Files ページで
/// パスワード ロック解除 → ファイルアップロード（JS 暗号化）→ 一覧表示（JS 復号）を検証。
/// </summary>
[Collection("Playwright")]
public class E2eeBrowserTests(PlaywrightWebAppFixture fixture)
{
    /// <summary>API で E2EE ボリュームを作成し、ボリューム名を返す（ロック解除パスワードは管理者パスワードと同一）。</summary>
    private async Task<string> CreateE2eeVolumeAsync()
    {
        string volName = $"pw-e2ee-{Guid.NewGuid():N}";
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(PlaywrightWebAppFixture.Username, PlaywrightWebAppFixture.Password, salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        CryptographicOperations.ZeroMemory(kek);

        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/e2ee/create-volume");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", fixture.Token);
        req.Content = JsonContent.Create(new
        {
            volumeName = volName,
            username = PlaywrightWebAppFixture.Username,
            wrappedMasterKey = new
            {
                kdf = new { algorithm = "pbkdf2-sha256", iterations = 1000, salt },
                wrappedMasterKey = new { algorithm = "aes-256-gcm", nonce, ciphertext = ct, tag },
            },
            chunkSize = 1048576,
        });
        var resp = await fixture.Http.SendAsync(req);
        Assert.True(resp.IsSuccessStatusCode, $"create-volume failed: {resp.StatusCode}");
        return volName;
    }

    /// <summary>
    /// E2EE ボリュームでファイルをアップロードすると、JS 側で暗号化→サーバー保存→JS 復号され、
    /// 一覧にプレーン名が表示される。これで JS(e2ee.js) ↔ サーバー(C# E2eeCrypto) の相互運用を実証する。
    /// </summary>
    [Fact]
    public async Task E2ee_UploadAppearsInList_JsCryptoRoundtrip()
    {
        string volName = await CreateE2eeVolumeAsync();

        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();

        var consoleErrors = new List<string>();
        page.Console += (_, msg) => { if (msg.Type == "error") consoleErrors.Add(msg.Text); };
        page.PageError += (_, err) => consoleErrors.Add($"PAGEERROR: {err}");
        var apiCalls = new List<string>();
        page.Response += (_, r) =>
        {
            if (r.Url.Contains("/api/", StringComparison.OrdinalIgnoreCase))
                apiCalls.Add($"{r.Url.Replace(fixture.BaseUrl, "")} -> {(int)r.Status}");
        };

        // Files ページへ遷移 → E2EE ロック解除画面
        await page.GotoAsync($"{fixture.BaseUrl}/files/{volName}");
        await page.WaitForFunctionAsync("() => document.querySelector('input[type=password]') !== null",
            options: new PageWaitForFunctionOptions { Timeout = 60000 });

        // パスワード入力（@bind は onchange のため Tab で change 発火）→ ロック解除
        await page.Locator("input[type=password]").FillAsync(PlaywrightWebAppFixture.Password);
        await page.Locator("input[type=password]").PressAsync("Tab");
        await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "ロック解除" }).ClickAsync();

        // ロック解除成功（「クライアント側暗号化有効」表示）を待つ
        try
        {
            await page.WaitForFunctionAsync(
                "() => document.body.textContent.includes('クライアント側暗号化有効')",
                options: new PageWaitForFunctionOptions { Timeout = 30000 });
        }
        catch (TimeoutException)
        {
            var alert = page.Locator(".alert-danger");
            var alertText = await alert.CountAsync() > 0 ? await alert.First.InnerTextAsync() : "(no alert)";
            Assert.Fail(
                $"E2EE ロック解除が完了しませんでした。アラート: {alertText}" +
                $"\nAPI 呼び出し: {(apiCalls.Count == 0 ? "(なし)" : string.Join(" | ", apiCalls))}" +
                $"\nコンソールエラー:\n  - {string.Join("\n  - ", consoleErrors)}");
        }

        // テストファイルをアップロード（実際の JS e2ee.js で暗号化される）
        const string fileName = "pw-upload-test.txt";
        string tmpFile = Path.Combine(Path.GetTempPath(), fileName);
        await File.WriteAllTextAsync(tmpFile, "hello e2ee from playwright");
        try
        {
            await page.SetInputFilesAsync("input[type=file]", tmpFile);

            // ファイル一覧にプレーン名が表示される（JS 暗号化→サーバー保存→JS 復号のラウンドトリップ成功）
            try
            {
                await page.WaitForFunctionAsync(
                    "() => document.body.textContent.includes('pw-upload-test.txt')",
                    options: new PageWaitForFunctionOptions { Timeout = 30000 });
            }
            catch (TimeoutException)
            {
                var alert = page.Locator(".alert-danger");
                var alertText = await alert.CountAsync() > 0 ? await alert.First.InnerTextAsync() : "(no alert)";
                Assert.Fail(
                    $"アップロード後、ファイル一覧に表示されませんでした。アラート: {alertText}" +
                    $"\nAPI 呼び出し: {(apiCalls.Count == 0 ? "(なし)" : string.Join(" | ", apiCalls))}" +
                    $"\nコンソールエラー:\n  - {string.Join("\n  - ", consoleErrors)}");
            }

            Assert.Contains("pw-upload-test.txt", await page.ContentAsync());
        }
        finally
        {
            File.Delete(tmpFile);
        }
    }
}
