using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// 全共有経路 × 共有制御条件のマトリクステスト（表形式で全組合せを網羅）。
/// 経路: grant (add-wrapped-key) / batch add / group member add / create-group /
/// grant-group / invitation 作成。
/// 条件: 全員有効 / sender 無効 / recipient 無効 / global 無効。
///
/// 期待結果の原則:
/// - sender 無効 → 403（共有の送信側は無効化アカウントであってはならない）
/// - recipient 無効 → 409 または skip 報告（無効化アカウントを共有先にしない。
///   ただし既存メンバーのアクセスは剥奪しない = データ欠損防止）
/// - global 無効 → 403（ユーザー単位の設定に関係なくサーバー全体で共有を停止）
/// - 全員有効 → 成功し、付与が実際に反映されること（ステータスだけでなく効果を検証）
/// </summary>
[Collection("Aspire")]
public class SharingPolicyMatrixApiTests(AspireFixture fixture)
{
    private HttpClient Http => fixture.Http;

    /// <summary>マトリクスの 1 行 = 条件と期待ステータス。</summary>
    private sealed record MatrixRow(Cond Condition, string Label, HttpStatusCode Expected);

    private enum Cond { AllEnabled, SenderDisabled, RecipientDisabled, GlobalDisabled }

    private static MatrixRow All(HttpStatusCode code) => new(Cond.AllEnabled, "全員有効", code);
    private static MatrixRow Sender(HttpStatusCode code) => new(Cond.SenderDisabled, "sender 無効", code);
    private static MatrixRow Recipient(HttpStatusCode code) => new(Cond.RecipientDisabled, "recipient 無効", code);
    private static MatrixRow Global(HttpStatusCode code) => new(Cond.GlobalDisabled, "global 無効", code);

    private HttpClient AuthClient(string token)
    {
        var c = new HttpClient { BaseAddress = Http.BaseAddress };
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return c;
    }

    private async Task<HttpClient> CreateUserClientAsync(string username, string password = "password1234567")
    {
        using var admin = AuthClient(fixture.Token);
        var resp = await admin.PostAsJsonAsync("/api/v1/account/users",
            new { username, password, role = "user" });
        Assert.True(resp.IsSuccessStatusCode || resp.StatusCode == HttpStatusCode.BadRequest);
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

    private async Task SetGlobalSharingAsync(bool enabled)
    {
        using var admin = AuthClient(fixture.Token);
        var resp = await admin.PutAsJsonAsync("/api/v1/settings/sharing", new { enabled });
        Assert.True(resp.IsSuccessStatusCode, $"set global sharing failed: {resp.StatusCode}");
    }

    /// <summary>呼び出しごとに新しい admin クライアントでユーザー共有フラグを設定する（undo 用）。</summary>
    private async Task SetUserSharingByAdminAsync(string username, bool enabled)
    {
        using var admin = AuthClient(fixture.Token);
        await SetUserSharingAsync(admin, username, enabled);
    }

    /// <summary>
    /// 条件を適用し、テスト終了時に必ず呼べる undo を返す。
    /// undo は呼び出しごとに新しい admin クライアントを作る（破棄済みクライアント参照を防ぐ）。
    /// （Aspire fixture は全テストクラス共有のため、設定漏れは後続テストを汚染する）
    /// </summary>
    private async Task<Func<Task>> ApplyConditionAsync(Cond condition, string sender, string recipient)
    {
        switch (condition)
        {
            case Cond.SenderDisabled:
                await SetUserSharingByAdminAsync(sender, false);
                return () => SetUserSharingByAdminAsync(sender, true);
            case Cond.RecipientDisabled:
                await SetUserSharingByAdminAsync(recipient, false);
                return () => SetUserSharingByAdminAsync(recipient, true);
            case Cond.GlobalDisabled:
                await SetGlobalSharingAsync(false);
                return () => SetGlobalSharingAsync(true);
            default:
                return () => Task.CompletedTask;
        }
    }

    /// <summary>ユーザー所有の E2EE ボリュームを作成する。</summary>
    private static async Task<string> CreateEcdhVolumeAsync(HttpClient client, string owner)
    {
        string volName = $"mtx-{Guid.NewGuid():N}";
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

    /// <summary>暗号化なしの通常ボリュームを作成する（grant-group は E2EE ボリューム非対応のため）。</summary>
    private static async Task<string> CreatePlainVolumeAsync(HttpClient client, string owner)
    {
        string volName = $"mtx-plain-{Guid.NewGuid():N}";
        var resp = await client.PostAsJsonAsync("/api/v1/volumes/",
            new { name = volName, username = owner, password = "vol-pass-1234", encrypted = false });
        Assert.True(resp.IsSuccessStatusCode, $"create plain volume failed: {resp.StatusCode}");
        return volName;
    }

    /// <summary>recipient の password から決定論的に identity 鍵を導出し masterKey を ECIES ラップする。</summary>
    private static (object Wrapped, byte[] Priv) BuildEcdhWrappedKey(byte[] masterKey, string recipient, string recipientPassword)
    {
        byte[] identitySalt = EcdhIdentityKey.GenerateIdentitySalt();
        var (pub, priv) = EcdhIdentityKey.DeriveKeyPair(
            recipient, recipientPassword, identitySalt, new KdfSpec("pbkdf2-sha256", 10000, 0, 0, 0));
        var (eph, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, pub);
        return (new
        {
            wrapType = "ecdh",
            kdf = new { algorithm = "none" },
            wrappedMasterKey = new { algorithm = "aes-256-gcm", nonce, ciphertext = ct, tag },
            ephemeralPublicKey = eph,
        }, priv);
    }

    /// <summary>recipient 宛ての wrapped key を取得して ECIES アンラップする。</summary>
    private static async Task<byte[]> FetchAndUnwrapAsync(HttpClient client, string vol, string username, byte[] priv)
    {
        var resp = await client.GetAsync($"/api/v1/e2ee/{vol}/wrapped-key/{Uri.EscapeDataString(username)}");
        Assert.True(resp.IsSuccessStatusCode, $"wrapped-key fetch failed: {resp.StatusCode}");
        var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var wrap = json.GetProperty("wrappedMasterKey");
        return E2eeCrypto.EcdhUnwrap(
            Convert.FromBase64String(wrap.GetProperty("nonce").GetString()!),
            Convert.FromBase64String(wrap.GetProperty("ciphertext").GetString()!),
            Convert.FromBase64String(wrap.GetProperty("tag").GetString()!),
            Convert.FromBase64String(json.GetProperty("ephemeralPublicKey").GetString()!),
            priv);
    }

    // ---- 1. grant (add-wrapped-key) マトリクス ----

    [Fact]
    public async Task Grant_Matrix_AllRoutesAndConditions()
    {
        MatrixRow[] rows =
        [
            All(HttpStatusCode.OK),
            Sender(HttpStatusCode.Forbidden),
            Recipient(HttpStatusCode.Conflict),
            Global(HttpStatusCode.Forbidden),
        ];

        foreach (var row in rows)
        {
            // 各行でユーザー・ボリュームを新規作成（状態漏出を防ぐ）
            string owner = $"mx-g-o-{Guid.NewGuid():N}";
            string member = $"mx-g-m-{Guid.NewGuid():N}";
            using var ownerClient = await CreateUserClientAsync(owner);
            using var memberClient = await CreateUserClientAsync(member);
            string vol = await CreateEcdhVolumeAsync(ownerClient, owner);

            byte[] masterKey = E2eeCrypto.GenerateMasterKey();
            var (wrapped, memberPriv) = BuildEcdhWrappedKey(masterKey, member, "password1234567");

            Func<Task> undo = await ApplyConditionAsync(row.Condition, owner, member);
            try
            {
                var resp = await ownerClient.PostAsJsonAsync($"/api/v1/e2ee/{vol}/add-wrapped-key",
                    new { username = member, wrappedMasterKey = wrapped });

                Assert.True(resp.StatusCode == row.Expected,
                    $"[{row.Label}] grant expected {row.Expected} but got {resp.StatusCode}");

                if (row.Condition == Cond.AllEnabled)
                {
                    // 成功行は付与が実際に反映（masterKey が欠損なく届く）ことを検証
                    Assert.Equal(masterKey, await FetchAndUnwrapAsync(memberClient, vol, member, memberPriv));
                }
            }
            finally
            {
                await undo();
            }
        }
    }

    // ---- 2. batch add マトリクス ----

    [Fact]
    public async Task BatchAdd_Matrix_AllRoutesAndConditions()
    {
        MatrixRow[] rows =
        [
            All(HttpStatusCode.OK),
            Sender(HttpStatusCode.Forbidden),
            Recipient(HttpStatusCode.OK), // batch は recipient 無効を 409 にせず skip 報告する（他の宛先を block しない）
            Global(HttpStatusCode.Forbidden),
        ];

        foreach (var row in rows)
        {
            string owner = $"mx-b-o-{Guid.NewGuid():N}";
            string member = $"mx-b-m-{Guid.NewGuid():N}";
            using var ownerClient = await CreateUserClientAsync(owner);
            using var memberClient = await CreateUserClientAsync(member);
            string vol = await CreateEcdhVolumeAsync(ownerClient, owner);

            byte[] masterKey = E2eeCrypto.GenerateMasterKey();
            var (wrapped, memberPriv) = BuildEcdhWrappedKey(masterKey, member, "password1234567");

            Func<Task> undo = await ApplyConditionAsync(row.Condition, owner, member);
            try
            {
                var resp = await ownerClient.PostAsJsonAsync($"/api/v1/e2ee/{vol}/add-wrapped-keys-batch",
                    new { wrappedKeys = new Dictionary<string, object> { [member] = wrapped } });

                Assert.True(resp.StatusCode == row.Expected,
                    $"[{row.Label}] batch expected {row.Expected} but got {resp.StatusCode}");
                if (resp.StatusCode != HttpStatusCode.OK) continue;

                var skipped = (await resp.Content.ReadFromJsonAsync<JsonElement>())
                    .GetProperty("skippedUsers").EnumerateArray().Select(e => e.GetString()).ToList();

                if (row.Condition == Cond.RecipientDisabled)
                {
                    // 無効 recipient は silent skip されず報告される
                    Assert.Equal([member], skipped);
                    // wrap は登録されない（アクセス権ごと無い）
                    var missing = await memberClient.GetAsync(
                        $"/api/v1/e2ee/{vol}/wrapped-key/{Uri.EscapeDataString(member)}");
                    Assert.True(missing.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound,
                        $"unexpected: {missing.StatusCode}");
                }
                else
                {
                    Assert.Empty(skipped);
                    Assert.Equal(masterKey, await FetchAndUnwrapAsync(memberClient, vol, member, memberPriv));
                }
            }
            finally
            {
                await undo();
            }
        }
    }

    // ---- 3. create-group マトリクス ----

    [Fact]
    public async Task CreateGroup_Matrix_AllRoutesAndConditions()
    {
        // グループは共有の単位のため recipient 条件は構造上存在しない
        MatrixRow[] rows =
        [
            All(HttpStatusCode.Created),
            Sender(HttpStatusCode.Forbidden),
            Global(HttpStatusCode.Forbidden),
        ];

        foreach (var row in rows)
        {
            string owner = $"mx-cg-o-{Guid.NewGuid():N}";
            string member = $"mx-cg-m-{Guid.NewGuid():N}";
            using var ownerClient = await CreateUserClientAsync(owner);
            await CreateUserClientAsync(member);

            Func<Task> undo = await ApplyConditionAsync(row.Condition, owner, member);
            try
            {
                string groupName = $"mx-grp-{Guid.NewGuid():N}";
                var resp = await ownerClient.PostAsJsonAsync("/api/v1/groups/",
                    new { groupName });

                Assert.True(resp.StatusCode == row.Expected,
                    $"[{row.Label}] create-group expected {row.Expected} but got {resp.StatusCode}");

                if (row.Condition == Cond.AllEnabled)
                {
                    var groups = await ownerClient.GetAsync("/api/v1/groups/");
                    Assert.Contains(groupName, await groups.Content.ReadAsStringAsync());
                }
            }
            finally
            {
                await undo();
            }
        }
    }

    // ---- 4. group member add マトリクス ----

    [Fact]
    public async Task AddGroupMember_Matrix_AllRoutesAndConditions()
    {
        MatrixRow[] rows =
        [
            All(HttpStatusCode.OK),
            Sender(HttpStatusCode.Forbidden),
            Recipient(HttpStatusCode.Conflict),
            Global(HttpStatusCode.Forbidden),
        ];

        foreach (var row in rows)
        {
            string owner = $"mx-gm-o-{Guid.NewGuid():N}";
            string member = $"mx-gm-m-{Guid.NewGuid():N}";
            using var ownerClient = await CreateUserClientAsync(owner);
            using var memberClient = await CreateUserClientAsync(member);

            string groupName = $"mx-grp-{Guid.NewGuid():N}";
            Assert.True((await ownerClient.PostAsJsonAsync("/api/v1/groups/", new { groupName }))
                .IsSuccessStatusCode);

            Func<Task> undo = await ApplyConditionAsync(row.Condition, owner, member);
            try
            {
                var resp = await ownerClient.PostAsJsonAsync($"/api/v1/groups/{Uri.EscapeDataString(groupName)}/members",
                    new { username = member });

                Assert.True(resp.StatusCode == row.Expected,
                    $"[{row.Label}] add-group-member expected {row.Expected} but got {resp.StatusCode}");

                if (row.Condition == Cond.AllEnabled)
                {
                    // オーナーのグループ一覧にメンバーが反映されていること
                    var groups = await ownerClient.GetAsync("/api/v1/groups/");
                    string body = await groups.Content.ReadAsStringAsync();
                    Assert.Contains(groupName, body);
                    Assert.Contains($"\"username\":\"{member}\"", body);
                }
            }
            finally
            {
                await undo();
            }
        }
    }

    // ---- 5. grant-group マトリクス ----

    [Fact]
    public async Task GrantGroup_Matrix_AllRoutesAndConditions()
    {
        // recipient 側の共有可否は AddGroupMember 時の Receive チェックで担保されるため、
        // ここでは sender / global を検証する（recipient 無効メンバーはグループに追加できない）
        MatrixRow[] rows =
        [
            All(HttpStatusCode.OK),
            Sender(HttpStatusCode.Forbidden),
            Global(HttpStatusCode.Forbidden),
        ];

        foreach (var row in rows)
        {
            string owner = $"mx-gg-o-{Guid.NewGuid():N}";
            string member = $"mx-gg-m-{Guid.NewGuid():N}";
            using var ownerClient = await CreateUserClientAsync(owner);
            using var memberClient = await CreateUserClientAsync(member);

            // 準備（条件適用前・全員有効状態で実施）: グループ作成 + メンバー追加 + 通常ボリューム作成
            string groupName = $"mx-grp-{Guid.NewGuid():N}";
            Assert.True((await ownerClient.PostAsJsonAsync("/api/v1/groups/", new { groupName }))
                .IsSuccessStatusCode);
            Assert.True((await ownerClient.PostAsJsonAsync(
                $"/api/v1/groups/{Uri.EscapeDataString(groupName)}/members", new { username = member }))
                .IsSuccessStatusCode);
            string vol = await CreatePlainVolumeAsync(ownerClient, owner);

            Func<Task> undo = await ApplyConditionAsync(row.Condition, owner, member);
            try
            {
                var resp = await ownerClient.PostAsJsonAsync($"/api/v1/volumes/{vol}/grant-group",
                    new { groupName });

                Assert.True(resp.StatusCode == row.Expected,
                    $"[{row.Label}] grant-group expected {row.Expected} but got {resp.StatusCode}");

                if (row.Condition == Cond.AllEnabled)
                {
                    // グループメンバーのボリューム一覧に反映されること（付与の実効果）
                    var volumes = await memberClient.GetAsync("/api/v1/volumes");
                    Assert.Contains(vol, await volumes.Content.ReadAsStringAsync());
                }
            }
            finally
            {
                await undo();
            }
        }
    }

    // ---- 6. invitation 作成マトリクス ----

    [Fact]
    public async Task CreateInvitation_Matrix_AllRoutesAndConditions()
    {
        MatrixRow[] rows =
        [
            All(HttpStatusCode.OK),
            Sender(HttpStatusCode.Forbidden),
            Recipient(HttpStatusCode.Conflict),
            Global(HttpStatusCode.Forbidden),
        ];

        foreach (var row in rows)
        {
            string owner = $"mx-inv-o-{Guid.NewGuid():N}";
            string target = $"mx-inv-t-{Guid.NewGuid():N}";
            using var ownerClient = await CreateUserClientAsync(owner);
            await CreateUserClientAsync(target);

            Func<Task> undo = await ApplyConditionAsync(row.Condition, owner, target);
            try
            {
                var resp = await ownerClient.PostAsJsonAsync("/api/v1/e2ee/invitations",
                    new { targetUsername = target });

                Assert.True(resp.StatusCode == row.Expected,
                    $"[{row.Label}] create-invitation expected {row.Expected} but got {resp.StatusCode}");

                if (row.Condition == Cond.AllEnabled)
                {
                    string invitationId = (await resp.Content.ReadFromJsonAsync<JsonElement>())
                        .GetProperty("invitationId").GetString()!;
                    Assert.False(string.IsNullOrEmpty(invitationId));
                    var get = await ownerClient.GetAsync($"/api/v1/e2ee/invitations/{Uri.EscapeDataString(invitationId)}");
                    Assert.Equal(HttpStatusCode.OK, get.StatusCode);
                }
            }
            finally
            {
                await undo();
            }
        }
    }

    // ---- 7. 招待 TOCTOU: 作成後の無効化で accept は fail closed ----

    [Fact]
    public async Task InvitationCreated_ThenRecipientDisabled_AcceptFailsClosed()
    {
        // 招待作成後に recipient が無効化された場合、作成時点の条件が満たしていても
        // accept は拒否される（作成時チェックの TOCTOU を accept 時チェックで塞ぐ）
        string owner = $"mx-tt-o-{Guid.NewGuid():N}";
        string target = $"mx-tt-t-{Guid.NewGuid():N}";
        using var ownerClient = await CreateUserClientAsync(owner);
        using var targetClient = await CreateUserClientAsync(target);

        var create = await ownerClient.PostAsJsonAsync("/api/v1/e2ee/invitations",
            new { targetUsername = target });
        Assert.True(create.IsSuccessStatusCode);
        string invitationId = (await create.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("invitationId").GetString()!;

        using var admin = AuthClient(fixture.Token);
        await SetUserSharingAsync(admin, target, false);
        try
        {
            var accept = await targetClient.PostAsJsonAsync(
                $"/api/v1/e2ee/invitations/{Uri.EscapeDataString(invitationId)}/accept",
                new
                {
                    encryptedPublicKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                    nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(12)),
                });
            Assert.Equal(HttpStatusCode.Forbidden, accept.StatusCode);
        }
        finally
        {
            await SetUserSharingAsync(admin, target, true);
        }

        // 再有効化後は accept が成功する（無効化が一時的でもデータ欠損しない）
        var acceptAfter = await targetClient.PostAsJsonAsync(
            $"/api/v1/e2ee/invitations/{Uri.EscapeDataString(invitationId)}/accept",
            new
            {
                encryptedPublicKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(12)),
            });
        Assert.True(acceptAfter.IsSuccessStatusCode, $"accept after re-enable failed: {acceptAfter.StatusCode}");
    }

    [Fact]
    public async Task InvitationCreated_ThenGlobalSharingDisabled_AcceptFailsClosed()
    {
        string owner = $"mx-tg-o-{Guid.NewGuid():N}";
        string target = $"mx-tg-t-{Guid.NewGuid():N}";
        using var ownerClient = await CreateUserClientAsync(owner);
        using var targetClient = await CreateUserClientAsync(target);

        var create = await ownerClient.PostAsJsonAsync("/api/v1/e2ee/invitations",
            new { targetUsername = target });
        Assert.True(create.IsSuccessStatusCode);
        string invitationId = (await create.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("invitationId").GetString()!;

        await SetGlobalSharingAsync(false);
        try
        {
            var accept = await targetClient.PostAsJsonAsync(
                $"/api/v1/e2ee/invitations/{Uri.EscapeDataString(invitationId)}/accept",
                new
                {
                    encryptedPublicKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                    nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(12)),
                });
            Assert.Equal(HttpStatusCode.Forbidden, accept.StatusCode);
        }
        finally
        {
            await SetGlobalSharingAsync(true);
        }

        var acceptAfter = await targetClient.PostAsJsonAsync(
            $"/api/v1/e2ee/invitations/{Uri.EscapeDataString(invitationId)}/accept",
            new
            {
                encryptedPublicKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(12)),
            });
        Assert.True(acceptAfter.IsSuccessStatusCode, $"accept after restore failed: {acceptAfter.StatusCode}");
    }

    // ---- revoke 系は共有ポリシーの対象外（常に許可）の保証 ----

    /// <summary>
    /// revoke 行 = 条件と「誰が revoke を実行するか」。revoke は共有ポリシーで
    /// ブロックされてはならない（ブロックされると剥奪漏れの鍵が残留し、
    /// rotate 時に存在しないメンバー扱いとの不整合が生じうる）。
    /// 全員有効 / owner 無効 / target 無効 / global 無効の全条件で 200 を期待する。
    /// </summary>
    private sealed record RevokeRow(Cond Condition, string Label, string Revoker);

    [Fact]
    public async Task Revoke_Matrix_AlwaysAllowedRegardlessOfSharingPolicy()
    {
        RevokeRow[] rows =
        [
            new(Cond.AllEnabled, "全員有効（owner が実行）", "owner"),
            new(Cond.SenderDisabled, "owner 無効（owner が実行）", "owner"),
            new(Cond.RecipientDisabled, "target 無効（owner が実行）", "owner"),
            new(Cond.GlobalDisabled, "global 無効（owner が実行）", "owner"),
        ];

        foreach (var row in rows)
        {
            string owner = $"rvk-o-{Guid.NewGuid():N}";
            string member = $"rvk-m-{Guid.NewGuid():N}";
            HttpClient ownerClient = await CreateUserClientAsync(owner);
            using HttpClient memberClient = await CreateUserClientAsync(member);
            string vol = await CreateEcdhVolumeAsync(ownerClient, owner);

            // member をボリュームに参加させる（v1 経路の ECIES wrap で鍵を登録）
            byte[] masterKey = E2eeCrypto.GenerateMasterKey();
            var (wrapped, _) = BuildEcdhWrappedKey(masterKey, member, "password1234567");
            var grant = await ownerClient.PostAsJsonAsync($"/api/v1/e2ee/{vol}/add-wrapped-key",
                new { username = member, wrappedMasterKey = wrapped });
            Assert.True(grant.IsSuccessStatusCode, $"[{row.Label}] add-wrapped-key failed: {grant.StatusCode}");

            Func<Task> undo = await ApplyConditionAsync(row.Condition, owner, member);
            try
            {
                // revoke は共有ポリシー（sender/recipient/global いずれの無効化）でも
                // ブロックされないこと
                var revoke = await ownerClient.PostAsJsonAsync($"/api/v1/volumes/{vol}/revoke",
                    new { targetUsername = member });
                Assert.True(revoke.IsSuccessStatusCode,
                    $"[{row.Label}] revoke が共有ポリシーでブロックされました: {revoke.StatusCode}");

                // 剥奪が実際に反映されること（効果の検証）:
                // - member はアクセス権喪失で wrapped-key が取得不能（HasAccess 再チェック → 403）
                var memberKey = await memberClient.GetAsync($"/api/v1/e2ee/{vol}/wrapped-key/{member}");
                Assert.True(memberKey.StatusCode == HttpStatusCode.Forbidden || memberKey.StatusCode == HttpStatusCode.NotFound,
                    $"[{row.Label}] revoke 後も member の wrapped-key が取得可能です: {memberKey.StatusCode}");
                var memberVols = await memberClient.GetAsync("/api/v1/volumes");
                var memberVolsJson = await memberVols.Content.ReadFromJsonAsync<JsonElement>();
                Assert.DoesNotContain(memberVolsJson.EnumerateArray(),
                    v => v.GetProperty("name").GetString() == vol);

                // - owner 自身の鍵とアクセスは無傷（データ欠損なし）
                var ownerKey = await ownerClient.GetAsync($"/api/v1/e2ee/{vol}/wrapped-key/{owner}");
                Assert.True(ownerKey.IsSuccessStatusCode,
                    $"[{row.Label}] revoke 後に owner の wrapped-key が失われました: {ownerKey.StatusCode}");
            }
            finally
            {
                await undo();
            }
        }
    }

    /// <summary>
    /// SharingEnabled の変更は管理者のみ（非 admin は 403 で拒否され、設定は変わらない）。
    /// 一般ユーザーが他人・自分自身の共有フラグを書き換えられないことの回帰テスト。
    /// </summary>
    [Fact]
    public async Task SetUserSharing_NonAdmin_Forbidden()
    {
        string user = $"rvk-n-{Guid.NewGuid():N}";
        using HttpClient userClient = await CreateUserClientAsync(user);

        // 他人への変更を拒否
        var other = $"rvk-t-{Guid.NewGuid():N}";
        using HttpClient otherClient = await CreateUserClientAsync(other);
        var respOther = await userClient.PutAsJsonAsync(
            $"/api/v1/account/users/{Uri.EscapeDataString(other)}/sharing",
            new { sharingEnabled = false });
        Assert.Equal(HttpStatusCode.Forbidden, respOther.StatusCode);

        // 自分自身への変更も拒否
        var respSelf = await userClient.PutAsJsonAsync(
            $"/api/v1/account/users/{Uri.EscapeDataString(user)}/sharing",
            new { sharingEnabled = false });
        Assert.Equal(HttpStatusCode.Forbidden, respSelf.StatusCode);

        // 設定が実際に変わっていないこと（変わっていると後続の共有テストが破綻する）
        using var admin = AuthClient(fixture.Token);
        await SetUserSharingAsync(admin, user, true);
        var users = await admin.GetAsync("/api/v1/account/users");
        var usersJson = await users.Content.ReadFromJsonAsync<JsonElement>();
        var dto = Assert.Single(usersJson.EnumerateArray(),
            u => u.GetProperty("userName").GetString() == user);
        Assert.True(dto.GetProperty("sharingEnabled").GetBoolean(),
            "非 admin の呼び出しで SharingEnabled が変更されてしまいました");
    }
}
