using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
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

    /// <summary>
    /// e2ee.js のチャンク nonce 導出が C# E2eeCrypto と revision 込みで相互運用できることを検証する。
    /// Dokan 差分保存で再暗号化されたチャンク（revision >= 1）は nonce に le32 revision が混入する。
    /// ブラウザ側が X-Chunk-Revision を読めないとそのようなチャンクは復号に失敗する（回帰防止）。
    /// 双方向を検証: C# 暗号化 (rev=1) → JS 復号、JS 暗号化 (rev=2) → C# 復号。
    /// </summary>
    [Fact]
    public async Task E2ee_JsChunkCrypto_MatchesCsharpForRevisedChunks()
    {
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();
        await page.GotoAsync(fixture.BaseUrl + "/",
            options: new PageGotoOptions { WaitUntil = WaitUntilState.Load });

        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] kekSalt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(PlaywrightWebAppFixture.Username, PlaywrightWebAppFixture.Password, kekSalt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        CryptographicOperations.ZeroMemory(kek);

        byte[] fileSalt = RandomNumberGenerator.GetBytes(16);
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        byte[] plain = Encoding.UTF8.GetBytes("revision cross-check payload");
        const int chunkIndex = 1;

        // C# で revision=1 で暗号化（Dokan 差分保存が生成する形式）
        byte[] encByCsharp = E2eeCrypto.EncryptChunk(plain, fileKey, chunkIndex, fileSalt,
            isFirstChunk: false, revision: 1);

        // JS 側: KEK 導出 → masterKey アンラップ → revision=1 の C# 暗号文を復号し、
        // 同一平文を revision=2 で再暗号化して返す
        string encByJsB64 = await page.EvaluateAsync<string>(@"async (args) => {
            const mod = await import(args.moduleUrl);
            const kekHandle = await mod.deriveKek(args.password, args.kekSaltB64, args.iterations, args.username);
            const mkHandle = await mod.unwrapMasterKey(args.nonceB64, args.ctB64, args.tagB64, kekHandle);

            const plainB64 = await mod.decryptChunk(
                args.encB64, mkHandle, args.chunkIndex, args.fileSaltB64, 1);
            return await mod.encryptChunk(
                plainB64, mkHandle, args.chunkIndex, args.fileSaltB64, false, 2);
        }", new
        {
            moduleUrl = $"{fixture.BaseUrl}/js/e2ee.js",
            password = PlaywrightWebAppFixture.Password,
            username = PlaywrightWebAppFixture.Username,
            kekSaltB64 = Convert.ToBase64String(kekSalt),
            iterations = 1000,
            nonceB64 = Convert.ToBase64String(nonce),
            ctB64 = Convert.ToBase64String(ct),
            tagB64 = Convert.ToBase64String(tag),
            encB64 = Convert.ToBase64String(encByCsharp),
            chunkIndex,
            fileSaltB64 = Convert.ToBase64String(fileSalt),
        });

        // JS 復号が正しいことの間接検証を含む: JS の revision=2 暗号文を C# で復号
        byte[] encByJs = Convert.FromBase64String(encByJsB64);
        byte[] decrypted = E2eeCrypto.DecryptChunk(encByJs, fileKey, chunkIndex, fileSalt, revision: 2);
        Assert.Equal(plain, decrypted);
    }

    /// <summary>
    /// ブラウザ e2ee.js の Argon2id+PBKDF2 合成 KDF (hash-wasm) が C# E2eeCrypto と
    /// 相互運用できることを検証する。CSP 配下での hash-wasm ロード、normalizeKdf の
    /// KDF オブジェクト経路、JS 側 Argon2id KEK が C# とビット一致することを含む（回帰防止）。
    /// </summary>
    [Fact]
    public async Task E2ee_Argon2idKek_BrowserMatchesCsharp()
    {
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();
        await page.GotoAsync(fixture.BaseUrl + "/",
            options: new PageGotoOptions { WaitUntil = WaitUntilState.Load });

        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] kekSalt = RandomNumberGenerator.GetBytes(16);
        // 軽量テストスペック (8 MiB / t=1 / p=1 + PBKDF2 10k)
        var spec = new KdfSpec(KdfSpec.Argon2id, Iterations: 10_000, MemoryKiB: 8192, Parallelism: 1, TimeCost: 1);

        // C# が Argon2id KEK で masterKey を wrap
        byte[] kek = E2eeCrypto.DeriveKek(PlaywrightWebAppFixture.Username, PlaywrightWebAppFixture.Password, kekSalt, spec);
        try
        {
            var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);

            // JS 側: 同一スペックの KDF オブジェクトで Argon2id KEK を導出 → masterKey アンラップ →
            // その鍵でファイル名を暗号化して返す
            string encNameB64 = await page.EvaluateAsync<string>(@"async (args) => {
                const mod = await import(args.moduleUrl);
                const kdf = {
                    algorithm: 'argon2id',
                    iterations: args.iterations,
                    memoryKiB: args.memoryKiB,
                    timeCost: args.timeCost,
                    parallelism: args.parallelism,
                };
                const kekHandle = await mod.deriveKek(args.password, args.kekSaltB64, kdf, args.username);
                const mkHandle = await mod.unwrapMasterKey(args.nonceB64, args.ctB64, args.tagB64, kekHandle);
                return await mod.encryptFilename('argon2-e2e-check.txt', mkHandle);
            }", new
            {
                moduleUrl = $"{fixture.BaseUrl}/js/e2ee.js",
                password = PlaywrightWebAppFixture.Password,
                username = PlaywrightWebAppFixture.Username,
                kekSaltB64 = Convert.ToBase64String(kekSalt),
                iterations = spec.Iterations,
                memoryKiB = spec.MemoryKiB,
                timeCost = spec.TimeCost,
                parallelism = spec.Parallelism,
                nonceB64 = Convert.ToBase64String(nonce),
                ctB64 = Convert.ToBase64String(ct),
                tagB64 = Convert.ToBase64String(tag),
            });

            // JS が正しい masterKey を復号できたことの間接検証（= JS の Argon2id KEK が C# と一致）
            string decryptedName = E2eeCrypto.DecryptFilename(encNameB64, masterKey);
            Assert.Equal("argon2-e2e-check.txt", decryptedName);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>
    /// ブラウザ e2ee.js の Argon2id 単独 KDF（PBKDF2 後段なし、argon2id-raw）が
    /// C# E2eeCrypto と相互運用できることを検証する（回帰防止）。
    /// </summary>
    [Fact]
    public async Task E2ee_Argon2idRawKek_BrowserMatchesCsharp()
    {
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();
        await page.GotoAsync(fixture.BaseUrl + "/",
            options: new PageGotoOptions { WaitUntil = WaitUntilState.Load });

        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] kekSalt = RandomNumberGenerator.GetBytes(16);
        // 軽量テストスペック (8 MiB / t=1 / p=1、PBKDF2 後段なし)
        var spec = new KdfSpec(KdfSpec.Argon2idRaw, Iterations: 0, MemoryKiB: 8192, Parallelism: 1, TimeCost: 1);

        byte[] kek = E2eeCrypto.DeriveKek(PlaywrightWebAppFixture.Username, PlaywrightWebAppFixture.Password, kekSalt, spec);
        try
        {
            var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);

            // JS 側: argon2id-raw の KDF オブジェクトで KEK を導出 → masterKey アンラップ →
            // ファイル名を暗号化して返す
            string encNameB64 = await page.EvaluateAsync<string>(@"async (args) => {
                const mod = await import(args.moduleUrl);
                const kdf = {
                    algorithm: 'argon2id-raw',
                    iterations: 0,
                    memoryKiB: args.memoryKiB,
                    timeCost: args.timeCost,
                    parallelism: args.parallelism,
                };
                const kekHandle = await mod.deriveKek(args.password, args.kekSaltB64, kdf, args.username);
                const mkHandle = await mod.unwrapMasterKey(args.nonceB64, args.ctB64, args.tagB64, kekHandle);
                return await mod.encryptFilename('argon2-raw-e2e-check.txt', mkHandle);
            }", new
            {
                moduleUrl = $"{fixture.BaseUrl}/js/e2ee.js",
                password = PlaywrightWebAppFixture.Password,
                username = PlaywrightWebAppFixture.Username,
                kekSaltB64 = Convert.ToBase64String(kekSalt),
                memoryKiB = spec.MemoryKiB,
                timeCost = spec.TimeCost,
                parallelism = spec.Parallelism,
                nonceB64 = Convert.ToBase64String(nonce),
                ctB64 = Convert.ToBase64String(ct),
                tagB64 = Convert.ToBase64String(tag),
            });

            // JS が正しい masterKey を復号できたことの間接検証（= JS の Argon2id 単独 KEK が C# と一致）
            string decryptedName = E2eeCrypto.DecryptFilename(encNameB64, masterKey);
            Assert.Equal("argon2-raw-e2e-check.txt", decryptedName);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>
    /// 共有 E2EE crypto format v2 のブラウザ (e2ee.js / Web Crypto) ↔ C# (E2eeV2) 相互運用を検証する:
    /// TOFU fingerprint、GroupKey の ECDH wrap 双方向、per-file DEK wrap、
    /// v2 チャンク暗号化双方向（AAD / nonce 導出の完全一致）（回帰防止）。
    /// </summary>
    [Fact]
    public async Task E2ee_V2SharedCrypto_BrowserMatchesCsharp()
    {
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();
        await page.GotoAsync(fixture.BaseUrl + "/",
            options: new PageGotoOptions { WaitUntil = WaitUntilState.Load });

        // 共通パラメータ
        const string volumeId = "pw-v2-volume";
        const string fileId = "abc123def4567890abcdef1234567890";
        const string username = "pw-bob";
        const int keyEpoch = 1;
        byte[] groupKey = E2eeV2.GenerateGroupKey();
        byte[] dek = E2eeV2.GenerateFileKey();
        byte[] fileSalt = E2eeV2.GenerateFileSalt();
        string groupKeyB64 = Convert.ToBase64String(groupKey);
        string dekB64 = Convert.ToBase64String(dek);
        string fileSaltB64 = Convert.ToBase64String(fileSalt);

        // C# 側 recipient 鍵ペア（JS wrap → C# unwrap 方向の受信者）
        var (recipientPub, recipientPriv) = E2eeCrypto.GenerateEcdhKeyPair();

        // フェーズ 1: JS 側 recipient 鍵ペアを生成してページに保持し、公開鍵 (raw 65B) を受け取る。
        // C# → JS 方向はこの公開鍵宛に wrap しないと秘密鍵が一致せず復号できない。
        string jsPubB64 = await page.EvaluateAsync<string>(@"async (args) => {
            const mod = await import(args.moduleUrl);
            const kp = await mod.generateKeyPair();
            window.__v2kp = kp;
            return await mod.exportPublicKey(kp.publicKeyHandle);
        }", new { moduleUrl = $"{fixture.BaseUrl}/js/e2ee.js" });

        // C# → JS: JS 側 recipient 公開鍵宛に GroupKey を wrap（JS がアンラップする）
        var (csEph, csNonce, csCt, csTag) = E2eeV2.EcdhWrapGroupKey(
            groupKey, Convert.FromBase64String(jsPubB64), volumeId, keyEpoch, username);

        // C# でチャンク (index=1, rev=0) を暗号化（JS が復号する）
        byte[] plain = Encoding.UTF8.GetBytes("v2 chunk from C# to browser");
        var ctx1 = new E2eeChunkContext(volumeId, fileId, 1, 0, keyEpoch);
        byte[] chunkByCsharp = E2eeV2.EncryptChunk(plain, dek, ctx1, isFirstChunk: false, fileSalt);

        string resultsJson = await page.EvaluateAsync<string>(@"async (args) => {
            const mod = await import(args.moduleUrl);

            // フェーズ 1 で生成した鍵ペア（C# はこの公開鍵宛に wrap 済み。
            // モジュールインスタンスはページ内で共有されるため鍵ハンドルも有効）
            const kp = window.__v2kp;

            const results = {};

            // TOFU fingerprint の一致
            results.fingerprint = await mod.computeFingerprint(args.recipientPubB64);

            // JS ECDH wrap → 呼び出し側 (C#) がアンラップする
            results.jsWrapped = await mod.ecdhWrapGroupKey(
                args.groupKeyB64, args.recipientPubB64, args.volumeId, args.keyEpoch, args.username);

            // C# wrap → JS アンラップ
            results.groupKeyFromCsharp = await mod.ecdhUnwrapGroupKey(
                args.csWrapNonceB64, args.csWrapCtB64, args.csWrapTagB64, args.csWrapEphPubB64,
                kp.privateKeyHandle, args.volumeId, args.keyEpoch, args.username);
            results.jsRecipientPub = await mod.exportPublicKey(kp.publicKeyHandle); // フェーズ 1 鍵ハンドルの生存検証も兼ねる

            // JS wrapFileKey → C# がアンラップする
            results.jsFileKeyWrap = await mod.wrapFileKey(
                args.dekB64, args.groupKeyB64, args.volumeId, args.fileId, args.keyEpoch);

            // C# 暗号化チャンク (index=1) を JS 復号
            results.chunkPlainFromCsharp = await mod.decryptChunkV2(
                args.csChunkEncB64, args.dekB64, 1, 0, args.keyEpoch,
                args.volumeId, args.fileId, args.fileSaltB64);

            // JS 暗号化チャンク (index=2) → C# が復号する
            results.jsChunkEnc = await mod.encryptChunkV2(
                results.chunkPlainFromCsharp, args.dekB64, 2, 0, args.keyEpoch,
                args.volumeId, args.fileId, args.fileSaltB64, false);

            return JSON.stringify(results); // Playwright .NET は JS オブジェクトを string に変換しないため明示的に serialize
        }", new
        {
            moduleUrl = $"{fixture.BaseUrl}/js/e2ee.js",
            recipientPubB64 = Convert.ToBase64String(recipientPub),
            groupKeyB64,
            dekB64,
            fileSaltB64,
            volumeId,
            fileId,
            username,
            keyEpoch,
            csWrapEphPubB64 = Convert.ToBase64String(csEph),
            csWrapNonceB64 = Convert.ToBase64String(csNonce),
            csWrapCtB64 = Convert.ToBase64String(csCt),
            csWrapTagB64 = Convert.ToBase64String(csTag),
            csChunkEncB64 = Convert.ToBase64String(chunkByCsharp),
        });

        // JS 側は匿名オブジェクトを返すため System.Text.Json で展開
        using var doc = System.Text.Json.JsonDocument.Parse(resultsJson);
        var r = doc.RootElement;

        // 1. fingerprint (TOFU): JS と C# が完全一致
        Assert.Equal(E2eeV2.ComputeFingerprint(recipientPub), r.GetProperty("fingerprint").GetString());

        // 2. JS wrap → C# unwrap: JS recipient 公開鍵は raw 65B
        byte[] jsPubRaw = Convert.FromBase64String(r.GetProperty("jsRecipientPub").GetString()!);
        Assert.Equal(65, jsPubRaw.Length);
        var jsWrap = r.GetProperty("jsWrapped");
        byte[] unwrapped = E2eeV2.EcdhUnwrapGroupKey(
            Convert.FromBase64String(jsWrap.GetProperty("nonce").GetString()!),
            Convert.FromBase64String(jsWrap.GetProperty("ciphertext").GetString()!),
            Convert.FromBase64String(jsWrap.GetProperty("tag").GetString()!),
            Convert.FromBase64String(jsWrap.GetProperty("ephemeralPublicKey").GetString()!),
            recipientPriv, volumeId, keyEpoch, username);
        Assert.Equal(groupKey, unwrapped);

        // 3. C# wrap → JS unwrap: JS が復号した GroupKey が元と一致
        Assert.Equal(groupKeyB64, r.GetProperty("groupKeyFromCsharp").GetString());

        // 4. JS wrapFileKey → C# unwrap
        var jfkw = r.GetProperty("jsFileKeyWrap");
        byte[] dekFromJs = E2eeV2.UnwrapFileKey(
            Convert.FromBase64String(jfkw.GetProperty("nonce").GetString()!),
            Convert.FromBase64String(jfkw.GetProperty("ciphertext").GetString()!),
            Convert.FromBase64String(jfkw.GetProperty("tag").GetString()!),
            groupKey, volumeId, fileId, keyEpoch);
        Assert.Equal(dek, dekFromJs);

        // 5. C# 暗号化チャンクの JS 復号結果が平文と一致
        Assert.Equal(plain, Convert.FromBase64String(r.GetProperty("chunkPlainFromCsharp").GetString()!));

        // 6. JS 暗号化チャンク (index=2) を C# 復号
        var ctx2 = new E2eeChunkContext(volumeId, fileId, 2, 0, keyEpoch);
        byte[] decryptedByCsharp = E2eeV2.DecryptChunk(
            Convert.FromBase64String(r.GetProperty("jsChunkEnc").GetString()!), dek, ctx2, fileSalt);
        Assert.Equal(plain, decryptedByCsharp);
    }
}
