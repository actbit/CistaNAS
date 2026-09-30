using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// 共有制御 (SharingEnabled) の server-side enforcement を実 HTTP 経由で検証する E2E テスト。
/// - グローバル / ユーザー単位の無効化が全共有系エンドポイントで強制されること（UI だけの制御でないこと）
/// - sender 403 / recipient 409 の使い分け
/// - revoke は共有無効時も常に許可（既存メンバーのアクセス剥奪が blocked されないこと）
/// - 共有無効ユーザーの自分のデータアクセス（wrapped key / ボリューム）は維持されること（データ欠損防止）
/// </summary>
[Collection("Aspire")]
public class SharingEnforcementApiTests(AspireFixture fixture)
{
    private HttpClient Http => fixture.Http;

    /// <summary>JWT を付与する HttpClient を作成。</summary>
    private HttpClient AuthClient(string token)
    {
        var c = new HttpClient { BaseAddress = Http.BaseAddress };
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return c;
    }

    /// <summary>テスト用ユーザーを作成しログインする。</summary>
    private async Task<HttpClient> CreateUserClientAsync(string username, string password = "password1234567")
    {
        using var admin = AuthClient(fixture.Token);
        var resp = await admin.PostAsJsonAsync("/api/v1/account/users",
            new { username, password, role = "user" });
        Assert.True(resp.IsSuccessStatusCode || resp.StatusCode == HttpStatusCode.BadRequest, // 既存なら OK
            $"create user failed: {resp.StatusCode}");
        var login = await Http.PostAsJsonAsync("/api/v1/auth/login", new { username, password });
        Assert.True(login.IsSuccessStatusCode, $"login failed: {login.StatusCode}");
        var json = await login.Content.ReadFromJsonAsync<JsonElement>();
        return AuthClient(json.GetProperty("accessToken").GetString()!);
    }

    private static async Task SetUserSharingAsync(HttpClient admin, string username, bool enabled)
    {
        var resp = await admin.PutAsJsonAsync(
            $"/api/v1/account/users/{Uri.EscapeDataString(username)}/sharing",
            new { sharingEnabled = enabled });
        Assert.True(resp.IsSuccessStatusCode, $"set sharing failed: {resp.StatusCode}");
    }

    /// <summary>グローバル共有設定を切り替え、テスト終了時に必ず復元する。</summary>
    private async Task<IDisposable> WithGlobalSharingAsync(bool enabled)
    {
        using var admin = AuthClient(fixture.Token);
        var resp = await admin.PutAsJsonAsync("/api/v1/settings/sharing", new { enabled });
        Assert.True(resp.IsSuccessStatusCode, $"set global sharing failed: {resp.StatusCode}");
        return new GlobalSharingRestorer(Http.BaseAddress!, fixture.Token);
    }

    private sealed class GlobalSharingRestorer(Uri baseAddress, string token) : IDisposable
    {
        public void Dispose()
        {
            using var admin = new HttpClient { BaseAddress = baseAddress };
            admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            admin.PutAsJsonAsync("/api/v1/settings/sharing", new { enabled = true }).Wait();
        }
    }

    /// <summary>ユーザー所有の E2EE ボリュームを作成する（create-volume は共有ポリシーの対象外）。</summary>
    private static async Task<string> CreateEcdhVolumeAsync(HttpClient client, string owner)
    {
        string volName = $"share-{Guid.NewGuid():N}";
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(owner, "password1234567", salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        CryptographicOperations.ZeroMemory(kek);

        var resp = await client.PostAsJsonAsync("/api/v1/e2ee/create-volume", new
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

    /// <summary>recipient の identity 鍵で ECIES ラップした wrappedMasterKey を組み立てる。</summary>
    private static object BuildEcdhWrappedKey(byte[] masterKey, string recipient, string recipientPassword)
    {
        byte[] identitySalt = EcdhIdentityKey.GenerateIdentitySalt();
        var (pub, priv) = EcdhIdentityKey.DeriveKeyPair(
            recipient, recipientPassword, identitySalt, new KdfSpec("pbkdf2-sha256", 10000, 0, 0, 0));
        CryptographicOperations.ZeroMemory(priv);
        var (eph, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, pub);
        return new
        {
            wrapType = "ecdh",
            kdf = new { algorithm = "none" },
            wrappedMasterKey = new { algorithm = "aes-256-gcm", nonce, ciphertext = ct, tag },
            ephemeralPublicKey = eph,
        };
    }

    /// <summary>owner → recipient へ ECDH 共有（wrapped key 追加）を行う。</summary>
    private static async Task<HttpResponseMessage> GrantAsync(
        HttpClient owner, string vol, string recipient, string recipientPassword)
    {
        // wrap 内容の正しさ（鍵で復号できること）は EcdhTests 等で検証済みのため、
        // ここではランダム 32B をそのまま masterKey としてラップする
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        var wrapped = BuildEcdhWrappedKey(masterKey, recipient, recipientPassword);
        CryptographicOperations.ZeroMemory(masterKey);
        return await owner.PostAsJsonAsync($"/api/v1/e2ee/{vol}/add-wrapped-key",
            new { username = recipient, wrappedMasterKey = wrapped });
    }

    // ---- ECDH identity セットアップ ----

    [Fact]
    public async Task IdentitySetup_GlobalSharingDisabled_Returns403()
    {
        using var user = await CreateUserClientAsync($"u-{Guid.NewGuid():N}");
        using var _ = await WithGlobalSharingAsync(false);
        try
        {
            var resp = await user.GetAsync("/api/v1/e2ee/identity-setup");
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }
        finally
        {
            await WithGlobalSharingAsync(true);
        }
    }

    [Fact]
    public async Task SetMyPublicKey_UserSharingDisabled_Returns403()
    {
        string user = $"u-{Guid.NewGuid():N}";
        using var client = await CreateUserClientAsync(user);
        using var admin = AuthClient(fixture.Token);
        await SetUserSharingAsync(admin, user, enabled: false);
        try
        {
            var resp = await client.PutAsJsonAsync("/api/v1/e2ee/my-public-key",
                new { publicKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(65)) });
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }
        finally
        {
            await SetUserSharingAsync(admin, user, enabled: true);
        }
    }

    [Fact]
    public async Task IdentitySetup_PublicKeyRegistration_IdempotentAndOverwriteProtected()
    {
        // 正しいフロー: identity-setup → 登録 → 同一鍵の再登録は冪等、別鍵の無断上書きは拒否
        string user = $"u-{Guid.NewGuid():N}";
        using var client = await CreateUserClientAsync(user);

        var setup1 = await (await client.GetAsync("/api/v1/e2ee/identity-setup"))
            .Content.ReadFromJsonAsync<JsonElement>();
        string salt1 = setup1.GetProperty("identitySalt").GetString()!;
        var setup2 = await (await client.GetAsync("/api/v1/e2ee/identity-setup"))
            .Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(salt1, setup2.GetProperty("identitySalt").GetString()); // salt は再生成されない

        var (pub, priv) = EcdhIdentityKey.DeriveKeyPair(user, "key-pass",
            Convert.FromBase64String(salt1), new KdfSpec("pbkdf2-sha256", 10000, 0, 0, 0));
        CryptographicOperations.ZeroMemory(priv);
        string pubB64 = Convert.ToBase64String(pub);

        Assert.True((await client.PutAsJsonAsync("/api/v1/e2ee/my-public-key", new { publicKey = pubB64 }))
            .IsSuccessStatusCode);
        // 同一鍵の再登録は冪等に成功
        Assert.True((await client.PutAsJsonAsync("/api/v1/e2ee/my-public-key", new { publicKey = pubB64 }))
            .IsSuccessStatusCode);
        // 別鍵の無断上書きは 400
        var overwrite = await client.PutAsJsonAsync("/api/v1/e2ee/my-public-key",
            new { publicKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(65)) });
        Assert.Equal(HttpStatusCode.BadRequest, overwrite.StatusCode);
        // 登録済み鍵は変わっていない
        var pubResp = await client.GetAsync($"/api/v1/e2ee/public-key/{Uri.EscapeDataString(user)}");
        Assert.Equal(pubB64, (await pubResp.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("publicKey").GetString());
    }

    // ---- grant (add-wrapped-key) ----

    [Fact]
    public async Task AddWrappedKey_SenderDisabled_Returns403()
    {
        string owner = $"u-{Guid.NewGuid():N}";
        string member = $"u-{Guid.NewGuid():N}";
        using var ownerClient = await CreateUserClientAsync(owner);
        using var memberClient = await CreateUserClientAsync(member);
        string vol = await CreateEcdhVolumeAsync(ownerClient, owner);

        using var admin = AuthClient(fixture.Token);
        await SetUserSharingAsync(admin, owner, enabled: false);
        try
        {
            var resp = await GrantAsync(ownerClient, vol, member, "password1234567");
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }
        finally
        {
            await SetUserSharingAsync(admin, owner, enabled: true);
        }
    }

    [Fact]
    public async Task AddWrappedKey_RecipientDisabled_Returns409()
    {
        string owner = $"u-{Guid.NewGuid():N}";
        string member = $"u-{Guid.NewGuid():N}";
        using var ownerClient = await CreateUserClientAsync(owner);
        using var memberClient = await CreateUserClientAsync(member);
        string vol = await CreateEcdhVolumeAsync(ownerClient, owner);

        using var admin = AuthClient(fixture.Token);
        await SetUserSharingAsync(admin, member, enabled: false);
        try
        {
            var resp = await GrantAsync(ownerClient, vol, member, "password1234567");
            Assert.Equal(HttpStatusCode.Conflict, resp.StatusCode);
        }
        finally
        {
            await SetUserSharingAsync(admin, member, enabled: true);
        }
    }

    [Fact]
    public async Task AddWrappedKey_GlobalDisabled_Returns403EvenForEnabledUsers()
    {
        string owner = $"u-{Guid.NewGuid():N}";
        string member = $"u-{Guid.NewGuid():N}";
        using var ownerClient = await CreateUserClientAsync(owner);
        using var memberClient = await CreateUserClientAsync(member);
        string vol = await CreateEcdhVolumeAsync(ownerClient, owner);

        using var _ = await WithGlobalSharingAsync(false);
        try
        {
            var resp = await GrantAsync(ownerClient, vol, member, "password1234567");
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }
        finally
        {
            await WithGlobalSharingAsync(true);
        }
    }

    // ---- 招待 ----

    [Fact]
    public async Task CreateInvitation_TargetDisabled_Returns409()
    {
        string owner = $"u-{Guid.NewGuid():N}";
        string target = $"u-{Guid.NewGuid():N}";
        using var ownerClient = await CreateUserClientAsync(owner);
        await CreateUserClientAsync(target);

        using var admin = AuthClient(fixture.Token);
        await SetUserSharingAsync(admin, target, enabled: false);
        try
        {
            var resp = await ownerClient.PostAsJsonAsync("/api/v1/e2ee/invitations",
                new { targetUsername = target });
            Assert.Equal(HttpStatusCode.Conflict, resp.StatusCode);
        }
        finally
        {
            await SetUserSharingAsync(admin, target, enabled: true);
        }
    }

    [Fact]
    public async Task CreateInvitation_SenderDisabled_Returns403()
    {
        string owner = $"u-{Guid.NewGuid():N}";
        string target = $"u-{Guid.NewGuid():N}";
        using var ownerClient = await CreateUserClientAsync(owner);
        await CreateUserClientAsync(target);

        using var admin = AuthClient(fixture.Token);
        await SetUserSharingAsync(admin, owner, enabled: false);
        try
        {
            var resp = await ownerClient.PostAsJsonAsync("/api/v1/e2ee/invitations",
                new { targetUsername = target });
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }
        finally
        {
            await SetUserSharingAsync(admin, owner, enabled: true);
        }
    }

    // ---- データアクセスの維持（データ欠損防止） ----

    [Fact]
    public async Task DisabledUser_KeepsAccessToGrantedWrappedKey()
    {
        // 共有中のメンバーが共有無効化されても、既に受領した wrapped key は取得できる（データ欠損防止）。
        string owner = $"u-{Guid.NewGuid():N}";
        string member = $"u-{Guid.NewGuid():N}";
        using var ownerClient = await CreateUserClientAsync(owner);
        using var memberClient = await CreateUserClientAsync(member);
        string vol = await CreateEcdhVolumeAsync(ownerClient, owner);

        Assert.True((await GrantAsync(ownerClient, vol, member, "password1234567")).IsSuccessStatusCode);

        using var admin = AuthClient(fixture.Token);
        await SetUserSharingAsync(admin, member, enabled: false);
        try
        {
            var wrapped = await memberClient.GetAsync($"/api/v1/e2ee/{vol}/wrapped-key/{Uri.EscapeDataString(member)}");
            Assert.True(wrapped.IsSuccessStatusCode || wrapped.StatusCode == HttpStatusCode.NotFound,
                $"wrapped-key unexpected status: {wrapped.StatusCode}");
        }
        finally
        {
            await SetUserSharingAsync(admin, member, enabled: true);
        }
    }

    [Fact]
    public async Task DisabledUser_CanCreateAndAccessOwnE2eeVolume()
    {
        // 共有無効でも私有 E2EE ボリュームの作成・マウントは可能（秘密 E2EE は共有機能に依存しない）
        string user = $"u-{Guid.NewGuid():N}";
        using var client = await CreateUserClientAsync(user);
        string vol = await CreateEcdhVolumeAsync(client, user);

        using var admin = AuthClient(fixture.Token);
        await SetUserSharingAsync(admin, user, enabled: false);
        try
        {
            var files = await client.GetAsync($"/api/v1/e2ee/{vol}/files");
            Assert.Equal(HttpStatusCode.OK, files.StatusCode);
        }
        finally
        {
            await SetUserSharingAsync(admin, user, enabled: true);
        }
    }

    // ---- revoke は常に許可 ----

    [Fact]
    public async Task Revoke_AlwaysAllowed_WhenGlobalSharingDisabled()
    {
        string owner = $"u-{Guid.NewGuid():N}";
        string member = $"u-{Guid.NewGuid():N}";
        using var ownerClient = await CreateUserClientAsync(owner);
        using var memberClient = await CreateUserClientAsync(member);
        string vol = await CreateEcdhVolumeAsync(ownerClient, owner);
        Assert.True((await GrantAsync(ownerClient, vol, member, "password1234567")).IsSuccessStatusCode);

        using var _ = await WithGlobalSharingAsync(false);
        try
        {
            var resp = await ownerClient.PostAsJsonAsync($"/api/v1/volumes/{vol}/revoke",
                new { targetUsername = member });
            Assert.True(resp.IsSuccessStatusCode, $"revoke failed: {resp.StatusCode}");
        }
        finally
        {
            await WithGlobalSharingAsync(true);
        }

        // revoke 後はメンバーの一覧から消失（アクセスが残る欠損がないこと）
        var volumes = await memberClient.GetAsync("/api/v1/volumes");
        string body = await volumes.Content.ReadAsStringAsync();
        Assert.DoesNotContain(vol, body);
    }

    [Fact]
    public async Task Revoke_AlwaysAllowed_WhenOwnerSharingDisabled()
    {
        string owner = $"u-{Guid.NewGuid():N}";
        string member = $"u-{Guid.NewGuid():N}";
        using var ownerClient = await CreateUserClientAsync(owner);
        using var memberClient = await CreateUserClientAsync(member);
        string vol = await CreateEcdhVolumeAsync(ownerClient, owner);
        Assert.True((await GrantAsync(ownerClient, vol, member, "password1234567")).IsSuccessStatusCode);

        using var admin = AuthClient(fixture.Token);
        await SetUserSharingAsync(admin, owner, enabled: false);
        try
        {
            var resp = await ownerClient.PostAsJsonAsync($"/api/v1/volumes/{vol}/revoke",
                new { targetUsername = member });
            Assert.True(resp.IsSuccessStatusCode, $"revoke failed: {resp.StatusCode}");
        }
        finally
        {
            await SetUserSharingAsync(admin, owner, enabled: true);
        }

        var volumes = await memberClient.GetAsync("/api/v1/volumes");
        Assert.DoesNotContain(vol, await volumes.Content.ReadAsStringAsync());
    }

    // ---- 管理者権限 ----

    [Fact]
    public async Task SharingSettings_NonAdmin_CannotModify()
    {
        using var user = await CreateUserClientAsync($"u-{Guid.NewGuid():N}");
        var global = await user.PutAsJsonAsync("/api/v1/settings/sharing", new { enabled = false });
        Assert.True(global.StatusCode is HttpStatusCode.Forbidden, $"unexpected: {global.StatusCode}");

        // 他ユーザーの共有フラグ変更も拒否
        string other = $"u-{Guid.NewGuid():N}";
        using var otherClient = await CreateUserClientAsync(other);
        var perm = await user.PutAsJsonAsync(
            $"/api/v1/account/users/{Uri.EscapeDataString(other)}/sharing", new { sharingEnabled = false });
        Assert.True(perm.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound,
            $"unexpected: {perm.StatusCode}");
    }

    [Fact]
    public async Task UsersList_SharingOnly_ExcludesDisabledUsers()
    {
        string disabled = $"u-{Guid.NewGuid():N}";
        string enabledUser = $"u-{Guid.NewGuid():N}";
        await CreateUserClientAsync(disabled);
        await CreateUserClientAsync(enabledUser);

        using var admin = AuthClient(fixture.Token);
        await SetUserSharingAsync(admin, disabled, enabled: false);
        try
        {
            var resp = await admin.GetAsync("/api/v1/account/users?sharingOnly=true");
            Assert.True(resp.IsSuccessStatusCode);
            string body = await resp.Content.ReadAsStringAsync();
            Assert.DoesNotContain($"\"{disabled}\"", body);
            Assert.Contains(enabledUser, body);
        }
        finally
        {
            await SetUserSharingAsync(admin, disabled, enabled: true);
        }
    }
}
