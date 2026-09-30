using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// 共有 v2 (GroupKey epoch) の rotate + revoke を実 HTTP 経由で検証する E2E テスト。
///
/// 「データ欠損ゼロ」の核心シナリオ:
/// - revoke (rotate-group-key) 時、SharingEnabled=false に切り替えられた「remaining member」
///   がいても、そのメンバー宛ての新 epoch wrap が登録されること（skip すると当該メンバーだけ
///   新 epoch のファイルが読めなくなる = SharingEnabled 切替による事実上の部分 revoke = データ欠損）
/// - skippedUsers が空で報告されること（silent skip / 誤った skip 報告がないこと）
/// - remaining member は旧 epoch の wrap も保持し、旧ファイルを継続して復号できること
/// - 剥奪メンバーからは wrap もアクセス権も完全に消えること
/// - 全メンバーが同一の volumeId を取得できること（volumeId が未永続のまま返ると
///   wrap の AAD が一致せず恒久的に unwrap 不能になる = 過去に発見した重大バグの回帰テスト）
/// </summary>
[Collection("Aspire")]
public class E2eeV2RotateApiTests(AspireFixture fixture)
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

    /// <summary>identity-setup → 導出 → サーバー登録までを行う。</summary>
    private static async Task<(byte[] Pub, byte[] Priv, string PubB64)> SetupIdentityAsync(
        HttpClient client, string username, string keyPassword)
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
        string pubB64 = Convert.ToBase64String(pub);
        var resp = await client.PutAsJsonAsync("/api/v1/e2ee/my-public-key", new { publicKey = pubB64 });
        Assert.True(resp.IsSuccessStatusCode, $"my-public-key failed: {resp.StatusCode}");
        return (pub, priv, pubB64);
    }

    private static async Task<string> CreateEcdhVolumeAsync(HttpClient ownerClient, string owner)
    {
        string volName = $"v2r-{Guid.NewGuid():N}";
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(owner, "password1234567", salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        CryptographicOperations.ZeroMemory(kek);

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

    /// <summary>GroupKey を recipient の identity 公開鍵で ECDH ラップする（rotate 送信用ペイロード）。</summary>
    private static object BuildGroupKeyWrap(byte[] groupKey, byte[] recipientPub, string volumeId, int epoch, string username)
    {
        var (eph, nonce, ct, tag) = E2eeV2.EcdhWrapGroupKey(groupKey, recipientPub, volumeId, epoch, username);
        return new
        {
            wrapType = "ecdh",
            kdf = new { algorithm = "none" },
            wrappedMasterKey = new { algorithm = "aes-256-gcm", nonce, ciphertext = ct, tag },
            ephemeralPublicKey = eph,
        };
    }

    private static async Task<JsonElement> GetGroupKeyInfoAsync(HttpClient client, string vol)
    {
        var resp = await client.GetAsync($"/api/v1/e2ee/{vol}/group-key-info");
        Assert.True(resp.IsSuccessStatusCode, $"group-key-info failed: {resp.StatusCode}");
        return await resp.Content.ReadFromJsonAsync<JsonElement>();
    }

    /// <summary>group-key-info から指定 epoch の wrap を取り出してアンラップする。</summary>
    private static byte[] UnwrapGroupKeyFromInfo(JsonElement info, int epoch, string username, byte[] priv)
    {
        string volumeId = info.GetProperty("volumeId").GetString()!;
        foreach (var w in info.GetProperty("myGroupKeys").EnumerateArray())
        {
            if (w.GetProperty("epoch").GetInt32() != epoch) continue;
            return E2eeV2.EcdhUnwrapGroupKey(
                Convert.FromBase64String(w.GetProperty("nonce").GetString()!),
                Convert.FromBase64String(w.GetProperty("ciphertext").GetString()!),
                Convert.FromBase64String(w.GetProperty("tag").GetString()!),
                Convert.FromBase64String(w.GetProperty("ephemeralPublicKey").GetString()!),
                priv, volumeId, epoch, username);
        }
        throw new InvalidOperationException($"epoch {epoch} の wrap が見つかりません（{username}）");
    }

    private static int[] WrapEpochs(JsonElement info)
        => [.. info.GetProperty("myGroupKeys").EnumerateArray().Select(w => w.GetProperty("epoch").GetInt32())];

    [Fact]
    public async Task Rotate_RevokeWithDisabledRemainingMember_KeepsAccessForAllRemainingMembers()
    {
        string owner = $"v2r-o-{Guid.NewGuid():N}";
        string kept = $"v2r-k-{Guid.NewGuid():N}";   // revoke 後も残るメンバー（途中で共有無効化される）
        string removed = $"v2r-r-{Guid.NewGuid():N}"; // revoke で剥奪されるメンバー
        using var ownerClient = await CreateUserClientAsync(owner);
        using var keptClient = await CreateUserClientAsync(kept);
        using var removedClient = await CreateUserClientAsync(removed);

        var (pubO, privO, regO) = await SetupIdentityAsync(ownerClient, owner, "kp-owner");
        var (pubK, privK, regK) = await SetupIdentityAsync(keptClient, kept, "kp-kept");
        var (pubR, privR, regR) = await SetupIdentityAsync(removedClient, removed, "kp-removed");
        try
        {
            // ---- 準備: ボリューム作成 + 2 メンバーへ masterKey を付与 ----
            string vol = await CreateEcdhVolumeAsync(ownerClient, owner);
            byte[] masterKeyK = E2eeCrypto.GenerateMasterKey();
            byte[] masterKeyR = E2eeCrypto.GenerateMasterKey();
            Assert.True((await ownerClient.PostAsJsonAsync($"/api/v1/e2ee/{vol}/add-wrapped-key",
                new { username = kept, wrappedMasterKey = BuildV1Grant(masterKeyK, pubK) })).IsSuccessStatusCode);
            Assert.True((await ownerClient.PostAsJsonAsync($"/api/v1/e2ee/{vol}/add-wrapped-key",
                new { username = removed, wrappedMasterKey = BuildV1Grant(masterKeyR, pubR) })).IsSuccessStatusCode);

            // ---- epoch 1: owner が GroupKey を配布（全員） ----
            var info0 = await GetGroupKeyInfoAsync(ownerClient, vol);
            Assert.Equal(0, info0.GetProperty("keyEpoch").GetInt32());
            string volumeId = info0.GetProperty("volumeId").GetString()!;
            Assert.False(string.IsNullOrEmpty(volumeId));

            byte[] groupKey1 = E2eeV2.GenerateGroupKey();
            var epoch1 = new Dictionary<string, object>
            {
                [owner] = BuildGroupKeyWrap(groupKey1, pubO, volumeId, 1, owner),
                [kept] = BuildGroupKeyWrap(groupKey1, pubK, volumeId, 1, kept),
                [removed] = BuildGroupKeyWrap(groupKey1, pubR, volumeId, 1, removed),
            };
            var rotate1 = await ownerClient.PostAsJsonAsync($"/api/v1/e2ee/{vol}/rotate-group-key",
                new { newEpoch = 1, wrappedGroupKeys = epoch1 });
            Assert.True(rotate1.IsSuccessStatusCode, $"rotate-1 failed: {rotate1.StatusCode}");
            Assert.Empty((await rotate1.Content.ReadFromJsonAsync<JsonElement>())
                .GetProperty("skippedUsers").EnumerateArray());

            // 全員が同一 volumeId・同一 GroupKey を得る（VolumeId 未永続バグの回帰:
            // 未永続 GUID がメンバーごとに再生成されると AAD 不一致で unwrap 失敗する）
            foreach (var (client, username, priv) in new[] { (ownerClient, owner, privO), (keptClient, kept, privK), (removedClient, removed, privR) })
            {
                var info = await GetGroupKeyInfoAsync(client, vol);
                Assert.Equal(1, info.GetProperty("keyEpoch").GetInt32());
                Assert.Equal(volumeId, info.GetProperty("volumeId").GetString());
                Assert.Equal(groupKey1, UnwrapGroupKeyFromInfo(info, 1, username, priv));
            }

            // ---- kept を共有無効化（既存メンバーのまま） ----
            using var admin = AuthClient(fixture.Token);
            Assert.True((await admin.PutAsJsonAsync(
                $"/api/v1/account/users/{Uri.EscapeDataString(kept)}/sharing", new { sharingEnabled = false }))
                .IsSuccessStatusCode);
            try
            {
                // ---- epoch 2: removed を剥奪する rotate。remaining = owner + kept（kept は共有無効） ----
                byte[] groupKey2 = E2eeV2.GenerateGroupKey();
                var epoch2 = new Dictionary<string, object>
                {
                    [owner] = BuildGroupKeyWrap(groupKey2, pubO, volumeId, 2, owner),
                    // 本修正の核心: SharingEnabled=false の remaining member (kept) 宛ても
                    // wrap を登録する（skip すると kept だけ新 epoch のファイルが読めなくなる）
                    [kept] = BuildGroupKeyWrap(groupKey2, pubK, volumeId, 2, kept),
                };
                var rotate2 = await ownerClient.PostAsJsonAsync($"/api/v1/e2ee/{vol}/rotate-group-key",
                    new { newEpoch = 2, wrappedGroupKeys = epoch2, removedUsername = removed });
                Assert.True(rotate2.IsSuccessStatusCode,
                    $"rotate-2 failed: {rotate2.StatusCode} {await rotate2.Content.ReadAsStringAsync()}");

                // skip されていないこと（誤った skip 報告もデータ欠損の誤検知になるため禁止）
                Assert.Empty((await rotate2.Content.ReadFromJsonAsync<JsonElement>())
                    .GetProperty("skippedUsers").EnumerateArray());

                // ---- kept（共有無効）は新 epoch も旧 epoch も読める ----
                var infoKept = await GetGroupKeyInfoAsync(keptClient, vol);
                Assert.Equal(2, infoKept.GetProperty("keyEpoch").GetInt32());
                Assert.Equal([1, 2], WrapEpochs(infoKept));
                Assert.Equal(groupKey2, UnwrapGroupKeyFromInfo(infoKept, 2, kept, privK)); // 新 epoch ファイル
                Assert.Equal(groupKey1, UnwrapGroupKeyFromInfo(infoKept, 1, kept, privK)); // 旧 epoch ファイル継続

                // 既存の masterKey wrap も維持される（既存アクセスの剥奪がないこと）
                var wk = await keptClient.GetAsync($"/api/v1/e2ee/{vol}/wrapped-key/{Uri.EscapeDataString(kept)}");
                Assert.True(wk.IsSuccessStatusCode, $"wrapped-key failed: {wk.StatusCode}");

                // ---- removed は完全に剥奪される ----
                var infoRemoved = await removedClient.GetAsync($"/api/v1/e2ee/{vol}/group-key-info");
                Assert.Equal(HttpStatusCode.Forbidden, infoRemoved.StatusCode); // アクセス権消失
                var volumes = await removedClient.GetAsync("/api/v1/volumes");
                Assert.DoesNotContain(vol, await volumes.Content.ReadAsStringAsync());

                // owner は新 epoch の GroupKey を取得できる
                var infoOwner = await GetGroupKeyInfoAsync(ownerClient, vol);
                Assert.Equal(groupKey2, UnwrapGroupKeyFromInfo(infoOwner, 2, owner, privO));
            }
            finally
            {
                await admin.PutAsJsonAsync(
                    $"/api/v1/account/users/{Uri.EscapeDataString(kept)}/sharing", new { sharingEnabled = true });
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privO);
            CryptographicOperations.ZeroMemory(privK);
            CryptographicOperations.ZeroMemory(privR);
        }
    }

    /// <summary>v1 経路 (add-wrapped-key) 用の ECIES wrap。</summary>
    private static object BuildV1Grant(byte[] masterKey, byte[] recipientPub)
    {
        var (eph, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, recipientPub);
        return new
        {
            wrapType = "ecdh",
            kdf = new { algorithm = "none" },
            wrappedMasterKey = new { algorithm = "aes-256-gcm", nonce, ciphertext = ct, tag },
            ephemeralPublicKey = eph,
        };
    }

    // ---- rotate バリデーション（データ欠損につながる誤操作の拒否） ----

    [Fact]
    public async Task Rotate_RejectsNonSequentialEpoch_RemovedWrap_AndUnknownMember()
    {
        string owner = $"v2r-v-o-{Guid.NewGuid():N}";
        string member = $"v2r-v-m-{Guid.NewGuid():N}";
        using var ownerClient = await CreateUserClientAsync(owner);
        using var memberClient = await CreateUserClientAsync(member);
        var (pubO, _, _) = await SetupIdentityAsync(ownerClient, owner, "kp");
        var (pubM, _, _) = await SetupIdentityAsync(memberClient, member, "kp");

        string vol = await CreateEcdhVolumeAsync(ownerClient, owner);
        var info0 = await GetGroupKeyInfoAsync(ownerClient, vol);
        string volumeId = info0.GetProperty("volumeId").GetString()!;

        // このテストでは member に鍵を付与していないため、wrap は owner のみ
        byte[] groupKey1 = E2eeV2.GenerateGroupKey();
        var epoch1 = new Dictionary<string, object>
        {
            [owner] = BuildGroupKeyWrap(groupKey1, pubO, volumeId, 1, owner),
        };

        // 剥奪対象に新 GroupKey をラップした rotate は拒否（revoke の基本要件）
        var withRemoved = new Dictionary<string, object>(epoch1)
        {
            [member] = BuildGroupKeyWrap(groupKey1, pubM, volumeId, 1, member),
        };
        var bad1 = await ownerClient.PostAsJsonAsync($"/api/v1/e2ee/{vol}/rotate-group-key",
            new { newEpoch = 1, wrappedGroupKeys = withRemoved, removedUsername = member });
        Assert.Equal(HttpStatusCode.BadRequest, bad1.StatusCode);

        // epoch の飛ばし・巻き戻しは拒否（厳密に +1 のみ）
        Assert.True((await ownerClient.PostAsJsonAsync($"/api/v1/e2ee/{vol}/rotate-group-key",
            new { newEpoch = 1, wrappedGroupKeys = epoch1 })).IsSuccessStatusCode);

        byte[] groupKey2 = E2eeV2.GenerateGroupKey();
        var bad2 = await ownerClient.PostAsJsonAsync($"/api/v1/e2ee/{vol}/rotate-group-key",
            new { newEpoch = 3, wrappedGroupKeys = new Dictionary<string, object> { [owner] = BuildGroupKeyWrap(groupKey2, pubO, volumeId, 3, owner) } });
        Assert.Equal(HttpStatusCode.BadRequest, bad2.StatusCode);
        var bad3 = await ownerClient.PostAsJsonAsync($"/api/v1/e2ee/{vol}/rotate-group-key",
            new { newEpoch = 1, wrappedGroupKeys = new Dictionary<string, object> { [owner] = BuildGroupKeyWrap(groupKey2, pubO, volumeId, 1, owner) } });
        Assert.Equal(HttpStatusCode.BadRequest, bad3.StatusCode);

        // メンバーでないユーザー宛ての wrap は拒否（先に add-wrapped-key が必要）
        string outsider = $"v2r-v-x-{Guid.NewGuid():N}";
        using var outsiderClient = await CreateUserClientAsync(outsider);
        var (pubX, _, _) = await SetupIdentityAsync(outsiderClient, outsider, "kp");
        var bad4 = await ownerClient.PostAsJsonAsync($"/api/v1/e2ee/{vol}/rotate-group-key",
            new
            {
                newEpoch = 2,
                wrappedGroupKeys = new Dictionary<string, object>
                {
                    [owner] = BuildGroupKeyWrap(groupKey2, pubO, volumeId, 2, owner),
                    [outsider] = BuildGroupKeyWrap(groupKey2, pubX, volumeId, 2, outsider),
                },
            });
        Assert.Equal(HttpStatusCode.BadRequest, bad4.StatusCode);

        // 非オーナーによる rotate は拒否（VolumeOwner ポリシーにより 403）
        var bad5 = await memberClient.PostAsJsonAsync($"/api/v1/e2ee/{vol}/rotate-group-key",
            new { newEpoch = 2, wrappedGroupKeys = new Dictionary<string, object> { [member] = BuildGroupKeyWrap(groupKey2, pubM, volumeId, 2, member) } });
        Assert.Equal(HttpStatusCode.Forbidden, bad5.StatusCode);

        // どの誤操作も epoch を進めていないこと（半端状態が残らない）
        var info = await GetGroupKeyInfoAsync(ownerClient, vol);
        Assert.Equal(1, info.GetProperty("keyEpoch").GetInt32());
    }
}
