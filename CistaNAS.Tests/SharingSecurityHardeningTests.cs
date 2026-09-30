using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// ECDH 共有 API のセキュリティハードニング（意図しない鍵の入手・書き換えを防ぐ）。
/// - 未認証リクエストは一括 401（鍵素材の有無すら漏らさない）
/// - 非メンバーは他人の wrapped key を取得・付与できない（横取り不可）
/// - 公開鍵の rotation は本人エンドポイントでのみ可能（他人の identity を乗っ取れない）
/// - ユーザー単位の共有フラグ変更は admin のみ
/// </summary>
[Collection("Aspire")]
public class SharingSecurityHardeningTests(AspireFixture fixture)
{
    private HttpClient AuthClient(string token)
    {
        var c = new HttpClient { BaseAddress = fixture.Http.BaseAddress };
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

    private async Task<string> CreateE2eeVolumeAsync(HttpClient ownerClient, string owner)
    {
        string volName = $"sec-{Guid.NewGuid():N}";
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
        return volName;
    }

    // ---- 未認証: 鍵素材の存在性すら漏らさない ----

    [Fact]
    public async Task AnonymousRequests_ToKeyMaterialEndpoints_All401()
    {
        var anon = new HttpClient { BaseAddress = fixture.Http.BaseAddress };

        var setup = await anon.GetAsync("/api/v1/e2ee/identity-setup");
        Assert.Equal(HttpStatusCode.Unauthorized, setup.StatusCode);

        var wrapped = await anon.GetAsync("/api/v1/e2ee/any-vol/wrapped-key/any-user");
        Assert.Equal(HttpStatusCode.Unauthorized, wrapped.StatusCode);

        var add = await anon.PostAsJsonAsync("/api/v1/e2ee/any-vol/add-wrapped-key",
            new { username = "u", wrappedMasterKey = new { } });
        Assert.Equal(HttpStatusCode.Unauthorized, add.StatusCode);

        var share = await anon.PutAsJsonAsync("/api/v1/account/users/u/sharing",
            new { sharingEnabled = false });
        Assert.Equal(HttpStatusCode.Unauthorized, share.StatusCode);
    }

    // ---- 非メンバー: 他人の wrapped key を取得・付与できない ----

    [Fact]
    public async Task NonMember_CannotFetchOthersWrappedKeys()
    {
        string owner = $"sec-o-{Guid.NewGuid():N}";
        string member = $"sec-m-{Guid.NewGuid():N}";
        string outsider = $"sec-x-{Guid.NewGuid():N}";
        using var ownerClient = await CreateUserClientAsync(owner);
        using var memberClient = await CreateUserClientAsync(member);
        using var outsiderClient = await CreateUserClientAsync(outsider);

        // member の identity 登録と wrap 付与
        var setup = await (await memberClient.GetAsync("/api/v1/e2ee/identity-setup"))
            .Content.ReadFromJsonAsync<JsonElement>();
        var (pub, priv) = EcdhIdentityKey.DeriveKeyPair(
            member, "kp", Convert.FromBase64String(setup.GetProperty("identitySalt").GetString()!),
            new KdfSpec("pbkdf2-sha256", 1_000, 0, 0, 0));
        try
        {
            await memberClient.PutAsJsonAsync("/api/v1/e2ee/my-public-key",
                new { publicKey = Convert.ToBase64String(pub) });

            string vol = await CreateE2eeVolumeAsync(ownerClient, owner);
            byte[] masterKey = E2eeCrypto.GenerateMasterKey();
            Assert.True((await ownerClient.PostAsJsonAsync(
                $"/api/v1/e2ee/{vol}/add-wrapped-key",
                new { username = member, wrappedMasterKey = BuildEcdhWrappedKey(masterKey, pub) }))
                .IsSuccessStatusCode);

            // 部外者は member 宛ての鍵を取得できない（VolumeAccess の外）
            var x1 = await outsiderClient.GetAsync(
                $"/api/v1/e2ee/{vol}/wrapped-key/{Uri.EscapeDataString(member)}");
            Assert.True(x1.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound,
                $"outsider fetched member key: {x1.StatusCode}");

            // 部外者は owner の鍵も取得できない
            var x2 = await outsiderClient.GetAsync(
                $"/api/v1/e2ee/{vol}/wrapped-key/{Uri.EscapeDataString(owner)}");
            Assert.True(x2.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound,
                $"outsider fetched owner key: {x2.StatusCode}");

            // 部外者は wrap を付与できない（鍵の差し替え防止）
            var add = await outsiderClient.PostAsJsonAsync(
                $"/api/v1/e2ee/{vol}/add-wrapped-key",
                new { username = member, wrappedMasterKey = BuildEcdhWrappedKey(
                    E2eeCrypto.GenerateMasterKey(), pub) });
            Assert.True(add.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound,
                $"outsider granted wrapped key: {add.StatusCode}");

            // 正規 recipient は影響を受けない（鍵は差し替わっておらず復元できる）
            var wrappedResp = await memberClient.GetAsync(
                $"/api/v1/e2ee/{vol}/wrapped-key/{Uri.EscapeDataString(member)}");
            Assert.True(wrappedResp.IsSuccessStatusCode, $"member fetch failed: {wrappedResp.StatusCode}");
            var wrapJson = await wrappedResp.Content.ReadFromJsonAsync<JsonElement>();
            var wrap = wrapJson.GetProperty("wrappedMasterKey");
            byte[] unwrapped = E2eeCrypto.EcdhUnwrap(
                Convert.FromBase64String(wrap.GetProperty("nonce").GetString()!),
                Convert.FromBase64String(wrap.GetProperty("ciphertext").GetString()!),
                Convert.FromBase64String(wrap.GetProperty("tag").GetString()!),
                Convert.FromBase64String(wrapJson.GetProperty("ephemeralPublicKey").GetString()!),
                priv);
            Assert.Equal(masterKey, unwrapped);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv);
        }
    }

    // ---- rotation は本人のみ: 他人の identity は乗っ取れない ----

    [Fact]
    public async Task PublicKeyRotation_IsSelfServiceOnly()
    {
        string alice = $"sec-a-{Guid.NewGuid():N}";
        string bob = $"sec-b-{Guid.NewGuid():N}";
        using var aliceClient = await CreateUserClientAsync(alice);
        using var bobClient = await CreateUserClientAsync(bob);

        // alice の identity 登録
        var setupA = await (await aliceClient.GetAsync("/api/v1/e2ee/identity-setup"))
            .Content.ReadFromJsonAsync<JsonElement>();
        var (pubA, _) = EcdhIdentityKey.DeriveKeyPair(
            alice, "kp", Convert.FromBase64String(setupA.GetProperty("identitySalt").GetString()!),
            new KdfSpec("pbkdf2-sha256", 1_000, 0, 0, 0));
        await aliceClient.PutAsJsonAsync("/api/v1/e2ee/my-public-key",
            new { publicKey = Convert.ToBase64String(pubA) });

        // bob が自分の鍵を rotate（本人は可能）
        var setupB = await (await bobClient.GetAsync("/api/v1/e2ee/identity-setup"))
            .Content.ReadFromJsonAsync<JsonElement>();
        var (pubB1, _) = EcdhIdentityKey.DeriveKeyPair(
            bob, "kp1", Convert.FromBase64String(setupB.GetProperty("identitySalt").GetString()!),
            new KdfSpec("pbkdf2-sha256", 1_000, 0, 0, 0));
        var (pubB2, _) = EcdhIdentityKey.DeriveKeyPair(
            bob, "kp2", Convert.FromBase64String(setupB.GetProperty("identitySalt").GetString()!),
            new KdfSpec("pbkdf2-sha256", 1_000, 0, 0, 0));
        await bobClient.PutAsJsonAsync("/api/v1/e2ee/my-public-key",
            new { publicKey = Convert.ToBase64String(pubB1) });
        Assert.True((await bobClient.PutAsJsonAsync("/api/v1/e2ee/my-public-key?rotate=true",
            new { publicKey = Convert.ToBase64String(pubB2) })).IsSuccessStatusCode);

        // 他人の鍵を直接書き換えるルートは存在しない（API 表面の担保）
        var hijack = await bobClient.PutAsJsonAsync(
            $"/api/v1/e2ee/public-key/{Uri.EscapeDataString(alice)}",
            new { publicKey = Convert.ToBase64String(pubB2) });
        Assert.True(hijack.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.MethodNotAllowed,
            $"hijack route unexpectedly exists: {hijack.StatusCode}");

        // alice の鍵は無傷（rotate は caller にのみ適用される）
        var afterA = await (await aliceClient.GetAsync("/api/v1/e2ee/identity-setup"))
            .Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(Convert.ToBase64String(pubA), afterA.GetProperty("publicKey").GetString());
    }

    // ---- ユーザー単位の共有フラグ変更は admin のみ ----

    [Fact]
    public async Task NonAdmin_CannotChangeUserSharingFlag()
    {
        string admin = AspireFixture.Username;
        string bob = $"sec-n-{Guid.NewGuid():N}";
        using var bobClient = await CreateUserClientAsync(bob);

        // 非本人・非 admin による変更は拒否
        var resp = await bobClient.PutAsJsonAsync(
            $"/api/v1/account/users/{Uri.EscapeDataString(bob)}/sharing", new { sharingEnabled = false });
        Assert.True(resp.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized,
            $"non-admin changed sharing flag: {resp.StatusCode}");

        // admin による変更は可能（機能が生きていることの対照確認）
        using var adminClient = AuthClient(fixture.Token);
        Assert.True((await adminClient.PutAsJsonAsync(
            $"/api/v1/account/users/{Uri.EscapeDataString(bob)}/sharing",
            new { sharingEnabled = true })).IsSuccessStatusCode);
    }
}
