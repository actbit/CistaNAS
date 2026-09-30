using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Shared.Crypto;
using Microsoft.Playwright;

namespace CistaNAS.PlaywrightTests;

/// <summary>
/// 共有制御 (SharingEnabled) と ECDH identity セットアップのブラウザ UI E2E テスト。
/// - Settings UI のグローバル / ユーザー単位共有スイッチが永続化されること
/// - Volumes UI の「共有」ボタンが共有無効時に非表示になること（UI 側の制御）
/// - identity 鍵セットアップ UI が実際に公開鍵を登録し、誤パスワードでは公開鍵を上書きしないこと
/// </summary>
[Collection("Playwright")]
public class SharingSettingsBrowserTests(PlaywrightWebAppFixture fixture)
{
    private const int WasmLoadTimeout = 60000;

    private HttpClient AdminHttp()
    {
        var c = new HttpClient
        {
            BaseAddress = fixture.Http.BaseAddress,
            DefaultRequestHeaders = { Authorization = new AuthenticationHeaderValue("Bearer", fixture.Token) },
        };
        return c;
    }

    /// <summary>テスト用ユーザーを作成する（既存ならスキップ）。</summary>
    private async Task CreateUserAsync(string username, string password)
    {
        using var admin = AdminHttp();
        var resp = await admin.PostAsJsonAsync("/api/v1/account/users",
            new { username, password, role = "user" });
        Assert.True(resp.IsSuccessStatusCode || resp.StatusCode == HttpStatusCode.BadRequest);
    }

    private async Task SetGlobalSharingAsync(bool enabled)
    {
        using var admin = AdminHttp();
        var resp = await admin.PutAsJsonAsync("/api/v1/settings/sharing", new { enabled });
        Assert.True(resp.IsSuccessStatusCode, $"set global sharing failed: {resp.StatusCode}");
    }

    private async Task SetUserSharingAsync(string username, bool enabled)
    {
        using var admin = AdminHttp();
        var resp = await admin.PutAsJsonAsync(
            $"/api/v1/account/users/{Uri.EscapeDataString(username)}/sharing", new { sharingEnabled = enabled });
        Assert.True(resp.IsSuccessStatusCode, $"set user sharing failed: {resp.StatusCode}");
    }

    private static async Task WaitForWasmAsync(IPage page, string jsPredicate) =>
        await page.WaitForFunctionAsync(jsPredicate,
            options: new PageWaitForFunctionOptions { Timeout = WasmLoadTimeout });

    /// <summary>ログイン画面から UI 操作でログインし /volumes へ遷移する。</summary>
    private async Task LoginViaUiAsync(IPage page, string username, string password)
    {
        await page.GotoAsync(fixture.BaseUrl + "/login");
        await WaitForWasmAsync(page, "() => document.querySelector('form') !== null");
        var usernameInput = page.Locator("form input").Nth(0);
        var passwordInput = page.Locator("form input[type=password]");
        await usernameInput.FillAsync(username);
        await usernameInput.PressAsync("Tab");
        await passwordInput.FillAsync(password);
        await passwordInput.PressAsync("Tab");
        await page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "ログイン" }).ClickAsync();
        await page.WaitForURLAsync("**/volumes", new PageWaitForURLOptions { Timeout = 30000 });
    }

    // ---- Settings UI: グローバル共有スイッチ ----

    [Fact]
    public async Task GlobalSharingSwitch_Toggle_PersistsAcrossReload()
    {
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync(fixture.BaseUrl + "/settings");
            await WaitForWasmAsync(page, "() => document.querySelector('#globalSharingSwitch') !== null");

            var sw = page.Locator("#globalSharingSwitch");
            Assert.True(await sw.IsCheckedAsync());

            // OFF にする（保存 PUT の完了を待ってから次へ進む。リロードが in-flight PUT を
            // 打ち切ると保存されない = テストの競合になるため）
            var putTask = page.WaitForResponseAsync(r =>
                r.Url.Contains("/api/v1/settings/sharing") && r.Request.Method == "PUT");
            await sw.ClickAsync();
            var putResp = await putTask;
            Assert.True(putResp.Ok, $"settings/sharing PUT failed: {putResp.Status}");
            await WaitForWasmAsync(page, "() => document.querySelector('#globalSharingSwitch')?.checked === false");

            // リロード後も OFF が維持される（サーバー永続化）。
            // スイッチの初期値は true のため、GET 応答が反映されて false に変わるのを待つ。
            await page.ReloadAsync();
            await WaitForWasmAsync(page, "() => document.querySelector('#globalSharingSwitch')?.checked === false");
            Assert.False(await page.Locator("#globalSharingSwitch").IsCheckedAsync());

            // ON に戻す（後続テストへの影響を除去）
            await page.Locator("#globalSharingSwitch").ClickAsync();
            await WaitForWasmAsync(page, "() => document.querySelector('#globalSharingSwitch')?.checked === true");
        }
        finally
        {
            await SetGlobalSharingAsync(true);
        }
    }

    // ---- Settings UI: ユーザー単位の共有チェックボックス ----

    [Fact]
    public async Task PerUserSharingCheckbox_Toggle_PersistsAcrossReload()
    {
        string user = $"ui-{Guid.NewGuid():N}";
        await CreateUserAsync(user, "password1234567");

        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();

        try
        {
            await page.GotoAsync(fixture.BaseUrl + "/settings");
            await WaitForWasmAsync(page,
                $"() => [...document.querySelectorAll('td')].some(td => td.textContent === '{user}')");

            var row = page.Locator("tr", new PageLocatorOptions { HasText = user });
            var checkbox = row.Locator("input.form-check-input");
            Assert.True(await checkbox.IsCheckedAsync());

            // チェックを外す（共有無効化）
            await checkbox.ClickAsync();
            await page.WaitForFunctionAsync(
                $"() => {{ const tr = [...document.querySelectorAll('tr')].find(r => r.textContent.includes('{user}')); return tr?.querySelector('input.form-check-input')?.checked === false; }}",
                options: new PageWaitForFunctionOptions { Timeout = 15000 });

            // リロード後も無効が維持される
            await page.ReloadAsync();
            await WaitForWasmAsync(page,
                $"() => [...document.querySelectorAll('td')].some(td => td.textContent === '{user}')");
            Assert.False(await page.Locator("tr", new PageLocatorOptions { HasText = user })
                .Locator("input.form-check-input").IsCheckedAsync());
        }
        finally
        {
            await SetUserSharingAsync(user, true);
        }
    }

    // ---- Volumes UI: 共有ボタンの表示制御 ----

    [Fact]
    public async Task VolumesPage_ShareButton_HiddenWhenGlobalSharingDisabled()
    {
        string vol = await CreateE2eeVolumeAsync();
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();

        try
        {
            // 共有有効時は「共有」ボタンが表示される
            await page.GotoAsync(fixture.BaseUrl + "/volumes");
            await WaitForWasmAsync(page,
                $"() => [...document.querySelectorAll('td')].some(td => td.textContent === '{vol}')");
            var shareButton = page.Locator("tr", new PageLocatorOptions { HasText = vol })
                .GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "共有" });
            Assert.True(await shareButton.IsVisibleAsync());

            // グローバル共有無効化 → ボタン非表示（強制自体はサーバー側。UI はこれを反映）
            await SetGlobalSharingAsync(false);
            await page.ReloadAsync();
            await WaitForWasmAsync(page,
                $"() => [...document.querySelectorAll('td')].some(td => td.textContent === '{vol}')");
            var shareAfter = page.Locator("tr", new PageLocatorOptions { HasText = vol })
                .GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "共有" });
            Assert.Equal(0, await shareAfter.CountAsync());

            // 復元 → 再表示
            await SetGlobalSharingAsync(true);
            await page.ReloadAsync();
            await WaitForWasmAsync(page,
                $"() => [...document.querySelectorAll('td')].some(td => td.textContent === '{vol}')");
            Assert.True(await page.Locator("tr", new PageLocatorOptions { HasText = vol })
                .GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "共有" }).IsVisibleAsync());
        }
        finally
        {
            await SetGlobalSharingAsync(true);
        }
    }

    // ---- Settings UI: identity 鍵セットアップフロー ----

    [Fact]
    public async Task IdentitySetupUi_RegisterVerify_RejectsWrongPassword_WithoutOverwrite()
    {
        string user = $"ui-{Guid.NewGuid():N}";
        const string keyPassword = "identity-key-pass-🎉";
        await CreateUserAsync(user, "password1234567");

        await using var context = await fixture.CreateAnonymousContextAsync();
        var page = await context.NewPageAsync();

        // UI からログイン
        await LoginViaUiAsync(page, user, "password1234567");
        await page.GotoAsync(fixture.BaseUrl + "/settings");

        var card = page.Locator(".card", new PageLocatorOptions { HasText = "E2EE 共有鍵（identity）管理" });
        await WaitForWasmAsync(page, "() => [...document.querySelectorAll('.card-header')].some(h => h.textContent.includes('E2EE 共有鍵（identity）管理'))");
        // RefreshData の identity-setup 応答（初期値は _keySetup=null → alert-secondary）が
        // 反映されて warning に切り替わるのを待ってから断言する
        await WaitForWasmAsync(page, "() => document.querySelector('.card .alert-warning') !== null");

        // 初期状態: 公開鍵未登録の警告
        var warning = card.Locator(".alert-warning");
        Assert.True(await warning.IsVisibleAsync());
        Assert.Contains("公開鍵が未登録", await warning.InnerTextAsync());

        var passwordInput = card.Locator("input[type=password]");
        var setupButton = card.Locator("button", new LocatorLocatorOptions { HasText = "identity 鍵を導出・登録" });

        // 導出・登録（Argon2id のため数秒かかる）
        await passwordInput.FillAsync(keyPassword);
        await passwordInput.PressAsync("Tab");
        await setupButton.ClickAsync();
        await WaitForWasmAsync(page,
            "() => [...document.querySelectorAll('.alert-success')].some(a => a.textContent.includes('秘密鍵はブラウザに保存されません'))");

        // サーバーに登録された公開鍵が C# 導出とバイト等価（UI → JS → サーバーの整合）
        await AssertRegisteredKeyMatchesCsharpAsync(user, keyPassword);

        // 誤パスワードでの再導出 → エラー表示、公開鍵は変更されない
        var verifyButton = card.Locator("button", new LocatorLocatorOptions { HasText = "鍵を再導出して検証" });
        await passwordInput.FillAsync("wrong-password");
        await passwordInput.PressAsync("Tab");
        await verifyButton.ClickAsync();
        await WaitForWasmAsync(page,
            "() => [...document.querySelectorAll('.alert-danger')].some(a => a.textContent.includes('一致しません'))");

        // 正しいパスワードでの再導出 → 一致メッセージ
        await passwordInput.FillAsync(keyPassword);
        await passwordInput.PressAsync("Tab");
        await verifyButton.ClickAsync();
        await WaitForWasmAsync(page,
            "() => [...document.querySelectorAll('.alert-success')].some(a => a.textContent.includes('一致しました'))");

        // 誤パスワード操作の後も登録鍵が不変（上書きされていないこと）
        await AssertRegisteredKeyMatchesCsharpAsync(user, keyPassword);
    }

    private async Task AssertRegisteredKeyMatchesCsharpAsync(string user, string keyPassword)
    {
        // ユーザーで API ログイン → identity-setup から salt / kdf / publicKey を取得
        var login = await fixture.Http.PostAsJsonAsync("/api/v1/auth/login",
            new { username = user, password = "password1234567" });
        Assert.True(login.IsSuccessStatusCode);
        var token = (await login.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("accessToken").GetString()!;

        using var client = new HttpClient
        {
            BaseAddress = fixture.Http.BaseAddress,
            DefaultRequestHeaders = { Authorization = new AuthenticationHeaderValue("Bearer", token) },
        };
        var setup = await (await client.GetAsync("/api/v1/e2ee/identity-setup"))
            .Content.ReadFromJsonAsync<JsonElement>();
        string saltB64 = setup.GetProperty("identitySalt").GetString()!;
        string registered = setup.GetProperty("publicKey").GetString()!;
        var kdf = setup.GetProperty("kdf");

        var spec = new KdfSpec(
            kdf.GetProperty("algorithm").GetString()!,
            kdf.GetProperty("iterations").GetInt32(),
            kdf.GetProperty("memoryKiB").GetInt32(),
            kdf.GetProperty("timeCost").GetInt32(),
            kdf.GetProperty("parallelism").GetInt32());
        var (pub, priv) = EcdhIdentityKey.DeriveKeyPair(
            user, keyPassword, Convert.FromBase64String(saltB64), spec);
        CryptographicOperations.ZeroMemory(priv);

        Assert.Equal(registered, Convert.ToBase64String(pub));
    }

    /// <summary>admin 所有の E2EE ボリュームを API で作成する（Volumes UI の「共有」ボタン表示用）。</summary>
    private async Task<string> CreateE2eeVolumeAsync()
    {
        string volName = $"ui-share-{Guid.NewGuid():N}";
        string owner = PlaywrightWebAppFixture.Username;
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(owner, PlaywrightWebAppFixture.Password, salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        CryptographicOperations.ZeroMemory(kek);
        CryptographicOperations.ZeroMemory(masterKey);

        using var admin = AdminHttp();
        var resp = await admin.PostAsJsonAsync("/api/v1/e2ee/create-volume", new
        {
            volumeName = volName,
            username = owner,
            wrappedMasterKey = new
            {
                kdf = new { algorithm = "pbkdf2-sha256", iterations = 1000, salt },
                wrappedMasterKey = new { algorithm = "aes-256-gcm", nonce, ciphertext = ct, tag },
            },
            chunkSize = 1048576,
        });
        Assert.True(resp.IsSuccessStatusCode, $"create-volume failed: {resp.StatusCode}");
        return volName;
    }
}
