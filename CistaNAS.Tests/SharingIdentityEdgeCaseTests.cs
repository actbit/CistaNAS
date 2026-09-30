using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

/// <summary>
/// SharingEnabled / ECDH identity 管理（AccountService + SharingPolicy）のエッジケーステスト。
/// データ欠損・誤上書き・fail-open を防ぐための境界条件を検証する。
/// </summary>
/// <remarks>
/// AccountService / SharingPolicy は scoped（1 リクエスト = 1 DbContext）。呼び出し毎に
/// fresh な scope で解決する。単一の scope を跨ぐと EF の tracked エンティティが stale になり、
/// 実挙動と異なる結果（他 scope での更新が見えない）を観測してしまう。
/// </remarks>
public class SharingIdentityEdgeCaseTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly CistaNasOptions _options;

    public SharingIdentityEdgeCaseTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _options = _sp.GetRequiredService<IOptions<CistaNasOptions>>().Value;
    }

    private async Task CreateUserAsync(string name)
    {
        using var scope = _sp.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<AccountService>()
            .CreateUserAsync(name, "password123", "user");
    }

    private async Task<bool> IsSharingEnabledAsync(string username)
    {
        using var scope = _sp.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<AccountService>()
            .IsSharingEnabledAsync(username);
    }

    private async Task SetSharingEnabledAsync(string username, bool enabled)
    {
        using var scope = _sp.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<AccountService>()
            .SetSharingEnabledAsync(username, enabled);
    }

    private async Task<bool> PolicyAllowsAsync(SharingAction action, string username)
    {
        using var scope = _sp.CreateAsyncScope();
        var policy = new SharingPolicy(Options.Create(_options),
            scope.ServiceProvider.GetRequiredService<AccountService>());
        return await policy.IsAllowedAsync(action, username);
    }

    private async Task<AccountService.EcdhIdentityInfo> GetIdentityAsync(string username)
    {
        using var scope = _sp.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<AccountService>()
            .GetOrCreateEcdhIdentityAsync(username);
    }

    private async Task UpdatePublicKeyAsync(string username, string publicKeyBase64, bool allowRotation = false)
    {
        using var scope = _sp.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<AccountService>()
            .UpdatePublicKeyAsync(username, publicKeyBase64, allowRotation);
    }

    private async Task<string?> GetPublicKeyAsync(string username)
    {
        using var scope = _sp.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<AccountService>()
            .GetPublicKeyAsync(username);
    }

    // ---- fail-closed（不在ユーザーでの誤許可を防ぐ） ----

    [Fact]
    public async Task IsSharingEnabled_UnknownUser_FailClosed()
    {
        Assert.False(await IsSharingEnabledAsync("no-such-user"));
    }

    [Theory]
    [InlineData(SharingAction.Send)]
    [InlineData(SharingAction.Receive)]
    [InlineData(SharingAction.SetupEcdh)]
    public async Task Policy_UnknownUser_DeniesAllActions(SharingAction action)
    {
        await CreateUserAsync("alice");
        Assert.False(await PolicyAllowsAsync(action, "no-such-user"));
    }

    [Theory]
    [InlineData(SharingAction.Send)]
    [InlineData(SharingAction.Receive)]
    [InlineData(SharingAction.SetupEcdh)]
    public async Task Policy_EmptyUsername_Denies(SharingAction action)
    {
        Assert.False(await PolicyAllowsAsync(action, ""));
    }

    // ---- ユーザー共有フラグの操作 ----

    [Fact]
    public async Task SetSharingEnabled_UnknownUser_Throws()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            using var scope = _sp.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<AccountService>()
                .SetSharingEnabledAsync("no-such-user", false);
        });
    }

    [Fact]
    public async Task SetSharingEnabled_SameValue_NoOp()
    {
        await CreateUserAsync("alice");
        // 既定 true → true の再設定はエラーにならない（冪等）
        await SetSharingEnabledAsync("alice", true);
        Assert.True(await IsSharingEnabledAsync("alice"));

        await SetSharingEnabledAsync("alice", false);
        await SetSharingEnabledAsync("alice", false);
        Assert.False(await IsSharingEnabledAsync("alice"));
    }

    [Fact]
    public async Task SetSharingEnabled_ReEnable_RestoresSharing()
    {
        // 無効化 →再有効化の往復でフラグとポリシー判定が元に戻る（片道しか効かない等の欠損がないこと）
        await CreateUserAsync("alice");

        await SetSharingEnabledAsync("alice", false);
        Assert.False(await IsSharingEnabledAsync("alice"));
        Assert.False(await PolicyAllowsAsync(SharingAction.Send, "alice"));

        await SetSharingEnabledAsync("alice", true);
        Assert.True(await IsSharingEnabledAsync("alice"));
        Assert.True(await PolicyAllowsAsync(SharingAction.Send, "alice"));
        Assert.True(await PolicyAllowsAsync(SharingAction.Receive, "alice"));
        Assert.True(await PolicyAllowsAsync(SharingAction.SetupEcdh, "alice"));
    }

    [Fact]
    public async Task CreateUser_Duplicate_Throws()
    {
        await CreateUserAsync("dup");
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var scope = _sp.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<AccountService>()
                .CreateUserAsync("dup", "password123", "user");
        });
    }

    [Fact]
    public async Task CreateUser_EmptyUsername_Throws()
    {
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var scope = _sp.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<AccountService>()
                .CreateUserAsync("", "password123", "user");
        });
    }

    // ---- ECDH identity の安定性（データ欠損防止の中核） ----

    [Fact]
    public async Task GetOrCreateEcdhIdentity_UnknownUser_Throws()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            using var scope = _sp.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<AccountService>()
                .GetOrCreateEcdhIdentityAsync("no-such-user");
        });
    }

    [Fact]
    public async Task EcdhIdentity_SaltSurvivesPublicKeyRotation()
    {
        // 公開鍵 rotation の前後で identity salt / version が不変。
        // salt が変わると既存メンバーが導出鍵で wrap を復号できなくなる（データ欠損）ため。
        await CreateUserAsync("alice");
        var before = await GetIdentityAsync("alice");

        await UpdatePublicKeyAsync("alice", Convert.ToBase64String(RandomNumberGenerator.GetBytes(65)));
        await UpdatePublicKeyAsync(
            "alice", Convert.ToBase64String(RandomNumberGenerator.GetBytes(65)), allowRotation: true);

        var after = await GetIdentityAsync("alice");
        Assert.Equal(before.IdentitySalt, after.IdentitySalt);
        Assert.Equal(before.DerivationVersion, after.DerivationVersion);
        Assert.NotEqual(before.PublicKey, after.PublicKey);
    }

    [Fact]
    public async Task UpdatePublicKey_NoExistingKey_AllowRotationFlagIrrelevant()
    {
        // 初回登録は rotation 指定の有無に関係なく成功する
        await CreateUserAsync("alice");
        string k1 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(65));
        await UpdatePublicKeyAsync("alice", k1, allowRotation: true);
        Assert.Equal(k1, await GetPublicKeyAsync("alice"));

        await CreateUserAsync("bob");
        string k2 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(65));
        await UpdatePublicKeyAsync("bob", k2, allowRotation: false);
        Assert.Equal(k2, await GetPublicKeyAsync("bob"));
    }

    [Fact]
    public async Task UpdatePublicKey_RotationToOldKey_StillRequiresRotation()
    {
        // rotation 後に「旧鍵へ戻す」操作も無断では拒否される（rollback 攻撃の防止）
        await CreateUserAsync("alice");
        string k1 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(65));
        string k2 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(65));

        await UpdatePublicKeyAsync("alice", k1);
        await UpdatePublicKeyAsync("alice", k2, allowRotation: true);

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            using var scope = _sp.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<AccountService>()
                .UpdatePublicKeyAsync("alice", k1);
        });
        Assert.Equal(k2, await GetPublicKeyAsync("alice"));
    }

    [Fact]
    public async Task UpdatePublicKey_UnknownUser_Throws()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            using var scope = _sp.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<AccountService>()
                .UpdatePublicKeyAsync("no-such-user", Convert.ToBase64String(RandomNumberGenerator.GetBytes(65)));
        });
    }

    [Fact]
    public async Task GetPublicKey_Unregistered_ReturnsNull()
    {
        await CreateUserAsync("alice");
        Assert.Null(await GetPublicKeyAsync("alice"));
    }

    // ---- 公開鍵と導出鍵の整合（誤った identity の永続化を防ぐ） ----

    [Fact]
    public async Task DerivedPublicKey_MatchesAfterRegistration_Roundtrip()
    {
        // 実際の導出 → 登録 → 再導出のフローで、同一パスワードからは登録鍵と同一の鍵が得られ、
        // 誤パスワードからは異なる鍵が得られることを検証（クライアント側検証ロジックの前提）。
        await CreateUserAsync("carol");
        var identity = await GetIdentityAsync("carol");

        var (pubCorrect, priv1) = EcdhIdentityKey.DeriveKeyPair(
            "carol", "correct-pass", identity.IdentitySalt, KdfSpec.DefaultArgon2id);
        CryptographicOperations.ZeroMemory(priv1);
        await UpdatePublicKeyAsync("carol", Convert.ToBase64String(pubCorrect));

        var (pubAgain, priv2) = EcdhIdentityKey.DeriveKeyPair(
            "carol", "correct-pass", identity.IdentitySalt, KdfSpec.DefaultArgon2id);
        CryptographicOperations.ZeroMemory(priv2);
        Assert.Equal(await GetPublicKeyAsync("carol"), Convert.ToBase64String(pubAgain));

        var (pubWrong, priv3) = EcdhIdentityKey.DeriveKeyPair(
            "carol", "wrong-pass", identity.IdentitySalt, KdfSpec.DefaultArgon2id);
        CryptographicOperations.ZeroMemory(priv3);
        Assert.NotEqual(await GetPublicKeyAsync("carol"), Convert.ToBase64String(pubWrong));
    }

    [Fact]
    public async Task SharingDisabled_IdentitySaltCreationStillPossible()
    {
        // 共有無効ユーザーの salt 取得自体は AccountService 層では拒否しない
        // （エンドポイント層で SharingPolicy が 403 を返す。無効ユーザーが後から
        //  共有を有効化したときに salt が欠損しないようにする）。
        await CreateUserAsync("dave");
        await SetSharingEnabledAsync("dave", false);
        var identity = await GetIdentityAsync("dave");
        Assert.Equal(EcdhIdentityKey.IdentitySaltSize, identity.IdentitySalt.Length);
        Assert.Equal(EcdhIdentityKey.CurrentDerivationVersion, identity.DerivationVersion);
    }

    [Fact]
    public async Task GlobalDisabled_PolicyDeniesEvenEnabledUser()
    {
        await CreateUserAsync("alice");
        _options.Sharing.Enabled = false;
        try
        {
            Assert.False(await PolicyAllowsAsync(SharingAction.Send, "alice"));
            Assert.False(await PolicyAllowsAsync(SharingAction.Receive, "alice"));
            Assert.False(await PolicyAllowsAsync(SharingAction.SetupEcdh, "alice"));
        }
        finally
        {
            _options.Sharing.Enabled = true;
        }
    }

    public async ValueTask DisposeAsync()
    {
        try { if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true); } catch (Exception) { }
        await ValueTask.CompletedTask;
    }
}
