using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// ECDH 共有フローの「データ欠損ゼロ」を実際の HTTP 経由で検証する E2E テスト。
/// - owner → member の ECIES ラップが全経路（identity 導出 → 登録 → wrap → 保存 → 取得 →
///   アンラップ）で masterKey を 1 バイトも欠損せず届けること
/// - identity-setup の KDF スペックが呼び出し間・ユーザー間で不変であること
///   （スペックが勝手に変わると既存全員の導出鍵が変わり ECDH wrap が全て復号不能 = データ欠損）
/// - 公開鍵 rotation が既存の wrapped key を破壊しないこと
/// - バッチ付与で共有無効受取先が silent skip されず報告され、半端状態が残らないこと
/// </summary>
[Collection("Aspire")]
public class EcdhShareRoundtripTests(AspireFixture fixture)
{
    private static readonly KdfSpec FastSpec = new("pbkdf2-sha256", 10_000, 0, 0, 0);

    private HttpClient AuthClient(string token)
    {
        var c = CistaNAS.Testing.LocalTestHttpClient.Create(fixture.Http.BaseAddress!);
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return c;
    }

    private async Task<HttpClient> CreateUserClientAsync(string username, string password = "password1234567")
    {
        using var admin = AuthClient(fixture.Token);
        var resp = await admin.PostAsJsonAsync("/api/v1/account/users",
            new { username, password, role = "user" });
        Assert.True(resp.IsSuccessStatusCode || resp.StatusCode == HttpStatusCode.BadRequest);
        var login = await fixture.Http.PostAsJsonAsync("/api/v1/auth/login", new { username, password });
        Assert.True(login.IsSuccessStatusCode, $"login failed: {login.StatusCode}");
        var json = await login.Content.ReadFromJsonAsync<JsonElement>();
        return AuthClient(json.GetProperty("accessToken").GetString()!);
    }

    /// <summary>identity-setup を取得し、返却された salt / KDF スペックで identity 鍵ペアを導出する。</summary>
    private static async Task<(byte[] Pub, byte[] Priv, string SaltB64, JsonElement Kdf, string PublicKeyB64)>
        DeriveIdentityViaSetupAsync(HttpClient client, string username, string keyPassword)
    {
        var setup = await (await client.GetAsync("/api/v1/e2ee/identity-setup"))
            .Content.ReadFromJsonAsync<JsonElement>();
        string saltB64 = setup.GetProperty("identitySalt").GetString()!;
        var kdf = setup.GetProperty("kdf");
        var spec = new KdfSpec(
            kdf.GetProperty("algorithm").GetString()!,
            kdf.GetProperty("iterations").GetInt32(),
            kdf.GetProperty("memoryKiB").GetInt32(),
            kdf.GetProperty("timeCost").GetInt32(),
            kdf.GetProperty("parallelism").GetInt32());

        var (pub, priv) = EcdhIdentityKey.DeriveKeyPair(username, keyPassword, Convert.FromBase64String(saltB64), spec);
        return (pub, priv, saltB64, kdf, Convert.ToBase64String(pub));
    }

    /// <summary>recipient の identity 公開鍵（サーバー登録済み）で masterKey を ECIES ラップする。</summary>
    private static object BuildEcdhWrappedKey(byte[] masterKey, byte[] recipientPublicKey)
    {
        var (eph, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, recipientPublicKey);
        return new
        {
            wrapType = "ecdh",
            kdf = new { algorithm = "none" },
            wrappedMasterKey = new { algorithm = "aes-256-gcm", nonce, ciphertext = ct, tag },
            ephemeralPublicKey = eph,
        };
    }

    /// <summary>公開鍵を登録する（失敗時はレスポンス本文を含めて失敗させる）。</summary>
    private static async Task RegisterPublicKeyAsync(HttpClient client, string publicKeyB64, bool rotate = false)
    {
        var resp = await client.PutAsJsonAsync(
            $"/api/v1/e2ee/my-public-key{(rotate ? "?rotate=true" : "")}", new { publicKey = publicKeyB64 });
        Assert.True(resp.IsSuccessStatusCode,
            $"my-public-key failed: {resp.StatusCode} {await resp.Content.ReadAsStringAsync()}");
    }

    private static async Task<HttpResponseMessage> GrantAsync(HttpClient owner, string vol, string recipient, byte[] recipientPublicKey, byte[] masterKey)
        => await owner.PostAsJsonAsync($"/api/v1/e2ee/{vol}/add-wrapped-key",
            new { username = recipient, wrappedMasterKey = BuildEcdhWrappedKey(masterKey, recipientPublicKey) });

    /// <summary>member 宛ての wrapped key を取得して ECIES アンラップする。</summary>
    private static async Task<byte[]> FetchAndUnwrapAsync(HttpClient client, string vol, string username, byte[] priv)
    {
        var resp = await client.GetAsync($"/api/v1/e2ee/{vol}/wrapped-key/{Uri.EscapeDataString(username)}");
        Assert.True(resp.IsSuccessStatusCode, $"wrapped-key fetch failed: {resp.StatusCode}");
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("ecdh", json.GetProperty("wrapType").GetString());

        var wrap = json.GetProperty("wrappedMasterKey");
        return E2eeCrypto.EcdhUnwrap(
            Convert.FromBase64String(wrap.GetProperty("nonce").GetString()!),
            Convert.FromBase64String(wrap.GetProperty("ciphertext").GetString()!),
            Convert.FromBase64String(wrap.GetProperty("tag").GetString()!),
            Convert.FromBase64String(json.GetProperty("ephemeralPublicKey").GetString()!),
            priv);
    }

    private static async Task<string> CreateEcdhVolumeAsync(HttpClient ownerClient, string owner)
    {
        string volName = $"rt-{Guid.NewGuid():N}";
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(owner, "password1234567", salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        CryptographicOperations.ZeroMemory(kek);
        CryptographicOperations.ZeroMemory(masterKey);

        var resp = await ownerClient.PostAsJsonAsync("/api/v1/e2ee/create-volume", new
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

        // create-volume は自動マウントされる（wrapped-key 取得の IsMounted 条件を満たす）
        return volName;
    }

    // ---- データ欠損ゼロの核心: フル ECIES ラウンドトリップ ----

    [Fact]
    public async Task FullRoundtrip_OwnerToMember_MasterKeySurvivesByteIdentical()
    {
        string owner = $"rt-o-{Guid.NewGuid():N}";
        string member = $"rt-m-{Guid.NewGuid():N}";
        using var ownerClient = await CreateUserClientAsync(owner);
        using var memberClient = await CreateUserClientAsync(member);

        // member: identity セットアップ → 導出 → 登録
        var (pub, priv, salt1, _, registered) = await DeriveIdentityViaSetupAsync(memberClient, member, "member-key-pass-🎉");
        try
        {
            await RegisterPublicKeyAsync(memberClient, registered);

            // owner: サーバー登録済み公開鍵で masterKey をラップして付与
            var pubResp = await ownerClient.GetAsync($"/api/v1/e2ee/public-key/{Uri.EscapeDataString(member)}");
            Assert.True(pubResp.IsSuccessStatusCode);
            string fetchedPub = (await pubResp.Content.ReadFromJsonAsync<JsonElement>())
                .GetProperty("publicKey").GetString()!;
            Assert.Equal(registered, fetchedPub); // 受取側の導出鍵とサーバー登録鍵の一致

            string vol = await CreateEcdhVolumeAsync(ownerClient, owner);
            byte[] masterKey = E2eeCrypto.GenerateMasterKey();
            Assert.True((await GrantAsync(ownerClient, vol, member, Convert.FromBase64String(fetchedPub), masterKey))
                .IsSuccessStatusCode);

            // member: 新セッション相当（再導出）でも同一 masterKey が復元される
            byte[] unwrapped = await FetchAndUnwrapAsync(memberClient, vol, member, priv);
            Assert.Equal(masterKey, unwrapped);

            var (_, privAgain, _, _, _) = await DeriveIdentityViaSetupAsync(memberClient, member, "member-key-pass-🎉");
            try
            {
                byte[] unwrappedAgain = await FetchAndUnwrapAsync(memberClient, vol, member, privAgain);
                Assert.Equal(masterKey, unwrappedAgain); // 決定論的導出 = プロセス再起動後も同一鍵
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privAgain);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv);
        }
    }

    // ---- identity-setup の KDF スペック不変性（契約ロック） ----

    [Fact]
    public async Task IdentitySetup_KdfSpec_StableAcrossCallsAndUsers()
    {
        // スペックがサーバー側設定やタイミングで変わると既存ユーザーの導出鍵が全て変わり、
        // ECDH wrap が復号不能になる（データ欠損）。スペックは固定であることを契約としてロックする。
        string u1 = $"rt-k1-{Guid.NewGuid():N}";
        string u2 = $"rt-k2-{Guid.NewGuid():N}";
        using var c1 = await CreateUserClientAsync(u1);
        using var c2 = await CreateUserClientAsync(u2);

        var (_, _, salt1a, kdf1a, _) = await DeriveIdentityViaSetupAsync(c1, u1, "kp");
        var (_, _, salt1b, kdf1b, _) = await DeriveIdentityViaSetupAsync(c1, u1, "kp");
        var (_, _, salt2, kdf2, _) = await DeriveIdentityViaSetupAsync(c2, u2, "kp");

        Assert.Equal(salt1a, salt1b);   // salt は再生成されない
        Assert.NotEqual(salt1a, salt2); // salt はユーザー毎
        Assert.Equal(kdf1a.GetRawText(), kdf1b.GetRawText()); // 同一ユーザー間で不変
        Assert.Equal(kdf1a.GetRawText(), kdf2.GetRawText()); // ユーザー間でも同一（サーバー全体で一意の導出仕様）
    }

    // ---- rotation は既存 wrap を破壊しない ----

    [Fact]
    public async Task PublicKeyRotation_ExistingWrappedKey_RetrievedAndUnwrappableWithOldKey()
    {
        string owner = $"rt-r-{Guid.NewGuid():N}";
        string member = $"rt-rm-{Guid.NewGuid():N}";
        using var ownerClient = await CreateUserClientAsync(owner);
        using var memberClient = await CreateUserClientAsync(member);

        var (pub, privOld, _, _, registered) = await DeriveIdentityViaSetupAsync(memberClient, member, "old-key-pass");
        try
        {
            await RegisterPublicKeyAsync(memberClient, registered);

            string vol = await CreateEcdhVolumeAsync(ownerClient, owner);
            byte[] masterKey = E2eeCrypto.GenerateMasterKey();
            Assert.True((await GrantAsync(ownerClient, vol, member, pub, masterKey)).IsSuccessStatusCode);

            // rotation（明示的フラグが必要）
            var (newPub, privNew, _, _, newRegistered) = await DeriveIdentityViaSetupAsync(memberClient, member, "new-key-pass");
            Assert.NotEqual(registered, newRegistered);
            await RegisterPublicKeyAsync(memberClient, newRegistered, rotate: true);

            // 既存 wrap は消失しない（rotation が wrap を破壊しないこと = データ欠損防止）
            byte[] unwrappedOld = await FetchAndUnwrapAsync(memberClient, vol, member, privOld);
            Assert.Equal(masterKey, unwrappedOld);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privOld);
        }
    }

    // ---- バッチ付与: silent skip なし・半端状態なし ----

    [Fact]
    public async Task BatchAdd_DisabledRecipient_SkippedReported_GrantSucceedsAfterReEnable()
    {
        string owner = $"rt-b-{Guid.NewGuid():N}";
        string enabled = $"rt-be-{Guid.NewGuid():N}";
        string disabled = $"rt-bd-{Guid.NewGuid():N}";
        using var ownerClient = await CreateUserClientAsync(owner);
        using var enabledClient = await CreateUserClientAsync(enabled);
        using var disabledClient = await CreateUserClientAsync(disabled);

        var (pubE, privE, _, _, regE) = await DeriveIdentityViaSetupAsync(enabledClient, enabled, "kp-e");
        var (pubD, privD, _, _, regD) = await DeriveIdentityViaSetupAsync(disabledClient, disabled, "kp-d");
        try
        {
            await RegisterPublicKeyAsync(enabledClient, regE);
            await RegisterPublicKeyAsync(disabledClient, regD);

            string vol = await CreateEcdhVolumeAsync(ownerClient, owner);

            // disabled を共有無効化
            using var admin = AuthClient(fixture.Token);
            Assert.True((await admin.PutAsJsonAsync(
                $"/api/v1/account/users/{Uri.EscapeDataString(disabled)}/sharing", new { sharingEnabled = false }))
                .IsSuccessStatusCode);

            // バッチ付与: disabled は skip されて報告される（silent skip / 半端登録がないこと）
            byte[] masterKeyE = E2eeCrypto.GenerateMasterKey();
            byte[] masterKeyD = E2eeCrypto.GenerateMasterKey();
            var batch = await ownerClient.PostAsJsonAsync($"/api/v1/e2ee/{vol}/add-wrapped-keys-batch",
                new
                {
                    wrappedKeys = new Dictionary<string, object>
                    {
                        [enabled] = BuildEcdhWrappedKey(masterKeyE, pubE),
                        [disabled] = BuildEcdhWrappedKey(masterKeyD, pubD),
                    },
                });
            Assert.True(batch.IsSuccessStatusCode, $"batch failed: {batch.StatusCode}");
            var skipped = (await batch.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("skippedUsers");
            Assert.Equal(disabled, skipped.EnumerateArray().Single().GetString());

            // enabled には wrap が届き、masterKey が欠損なく復元される
            Assert.Equal(masterKeyE, await FetchAndUnwrapAsync(enabledClient, vol, enabled, privE));

            // disabled には wrap が存在しない（アクセス権ごと無い → 403、または 404）
            var missing = await disabledClient.GetAsync($"/api/v1/e2ee/{vol}/wrapped-key/{Uri.EscapeDataString(disabled)}");
            Assert.True(missing.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound,
                $"unexpected status for skipped recipient: {missing.StatusCode}");

            // 再有効化後は付与できる
            Assert.True((await admin.PutAsJsonAsync(
                $"/api/v1/account/users/{Uri.EscapeDataString(disabled)}/sharing", new { sharingEnabled = true }))
                .IsSuccessStatusCode);
            Assert.True((await GrantAsync(ownerClient, vol, disabled, pubD, masterKeyD)).IsSuccessStatusCode);
            Assert.Equal(masterKeyD, await FetchAndUnwrapAsync(disabledClient, vol, disabled, privD));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privE);
            CryptographicOperations.ZeroMemory(privD);
        }
    }
}
