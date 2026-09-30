using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

/// <summary>
/// 決定論的 ECDH identity 鍵導出のテスト。
/// - 同一入力 → 同一鍵ペア（決定論性）
/// - 異なる入力（password / username / salt）→ 異なる鍵
/// - username 正規化（Trim + lowercase、culture 非依存）
/// - 固定テストベクトル（仕様固定。変更は破壊的変更）
/// - scalar は 1 &lt;= d &lt; n の範囲（rejection sampling、mod n 不使用）
/// - 導出鍵による ECDH 合意の成立
/// </summary>
public class EcdhIdentityKeyTests
{
    private static readonly byte[] FixedSalt = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

    /// <summary>テスト用の軽量 Argon2id 合成スペック（本番既定より小さいが同一アルゴリズム経路）。</summary>
    private static readonly KdfSpec TestSpec = new("argon2id", 1000, 8192, 2, 1);

    [Fact]
    public void Derive_SameInputs_ProducesIdenticalKeyPair()
    {
        var (pub1, priv1) = EcdhIdentityKey.DeriveKeyPair("alice", "correct horse", FixedSalt, TestSpec);
        var (pub2, priv2) = EcdhIdentityKey.DeriveKeyPair("alice", "correct horse", FixedSalt, TestSpec);
        try
        {
            Assert.Equal(pub1, pub2);
            Assert.Equal(priv1, priv2);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv1);
            CryptographicOperations.ZeroMemory(priv2);
        }
    }

    [Theory]
    [InlineData("wrong horse", "alice")]
    [InlineData("correct horse", "bob")]
    public void Derive_DifferentInputs_ProducesDifferentKeys(string password, string username)
    {
        var (basePub, _) = EcdhIdentityKey.DeriveKeyPair("alice", "correct horse", FixedSalt, TestSpec);
        var (otherPub, otherPriv) = EcdhIdentityKey.DeriveKeyPair(username, password, FixedSalt, TestSpec);
        CryptographicOperations.ZeroMemory(otherPriv);
        Assert.NotEqual(basePub, otherPub);
    }

    [Fact]
    public void Derive_DifferentSalt_ProducesDifferentKeys()
    {
        var (pub1, _) = EcdhIdentityKey.DeriveKeyPair("alice", "pw", FixedSalt, TestSpec);
        var salt2 = (byte[])FixedSalt.Clone();
        salt2[0] ^= 0x01;
        var (pub2, _) = EcdhIdentityKey.DeriveKeyPair("alice", "pw", salt2, TestSpec);
        Assert.NotEqual(pub1, pub2);
    }

    [Fact]
    public void Derive_UsernameIsNormalized_TrimAndCaseInsensitive()
    {
        var (basePub, _) = EcdhIdentityKey.DeriveKeyPair("alice", "pw", FixedSalt, TestSpec);
        var (variantPub, variantPriv) = EcdhIdentityKey.DeriveKeyPair("  Alice ", "pw", FixedSalt, TestSpec);
        CryptographicOperations.ZeroMemory(variantPriv);
        Assert.Equal(basePub, variantPub);
    }

    /// <summary>
    /// 固定テストベクトル。仕様（KDF 入力規約 + HKDF ドメイン分離 + scalar rejection sampling +
    /// P-256 公開鍵導出）を固定し、意図しない変更を破壊的変更として検出する。
    /// browser e2ee.js / Mobile（同一 Shared コード）はこのベクトルで相互運性を担保する。
    /// </summary>
    [Theory]
    [InlineData("argon2id", "BOIpydTKIL0yfvUbBie+C8SUCkYmlbjDH/c8/rcWBanLDB57U5S/P+O9Hg1XCAozcu/2GbFQha3peA/MHCnnzTI=")]
    [InlineData("argon2id-raw", "BNJjTwnQ8joKnLn8sZDoQLg1PH+eXiuTS7Jvcg2VvweV8e42z0ZUEs9rMb0xd6IlT1SLFeJfhscDfuF+FtW772Y=")]
    [InlineData("pbkdf2-sha256", "BB6af4KAqjTrIPOolArz6Q+NBKAgb0Oe4alSaelqEhc09jM/X8dsJ7f1EymdAy221Eqe2MISLhMTvA5Whx4RhfY=")]
    public void Derive_FixedVector_MatchesSpecification(string algorithm, string expectedPublicKeyBase64)
    {
        var spec = algorithm == "pbkdf2-sha256"
            ? new KdfSpec("pbkdf2-sha256", 10000, 0, 0, 0)
            : new KdfSpec(algorithm, 1000, 8192, 2, 1);
        var (pub, priv) = EcdhIdentityKey.DeriveKeyPair("alice", "s3cret-pass", FixedSalt, spec);
        CryptographicOperations.ZeroMemory(priv);
        Assert.Equal(expectedPublicKeyBase64, Convert.ToBase64String(pub));
    }

    [Fact]
    public void DeriveScalar_AlwaysInValidRange()
    {
        // ランダム seed 100 個で scalar が必ず有効範囲（1 <= d < n）に収まること。
        // CreateFromScalar は無効 scalar を拒否するため、構築成功自体が検証になる。
        for (int i = 0; i < 100; i++)
        {
            byte[] seed = RandomNumberGenerator.GetBytes(32);
            byte[] scalar = EcdhIdentityKey.DeriveScalar(seed);
            CryptographicOperations.ZeroMemory(seed);
            Assert.Equal(32, scalar.Length);
            using var ecdh = EcdhIdentityKey.CreateFromScalar(scalar);
            Assert.Equal(256, ecdh.KeySize);
            CryptographicOperations.ZeroMemory(scalar);
        }
    }

    [Fact]
    public void DeriveScalar_IsDeterministic()
    {
        byte[] seed = RandomNumberGenerator.GetBytes(32);
        byte[] s1 = EcdhIdentityKey.DeriveScalar(seed);
        byte[] s2 = EcdhIdentityKey.DeriveScalar(seed);
        CryptographicOperations.ZeroMemory(seed);
        Assert.Equal(s1, s2);
        CryptographicOperations.ZeroMemory(s1);
        CryptographicOperations.ZeroMemory(s2);
    }

    [Fact]
    public void DerivedKeys_PerformEcdhAgreement()
    {
        var (pubA, privA) = EcdhIdentityKey.DeriveKeyPair("alice", "pw-a", FixedSalt, TestSpec);
        var (pubB, privB) = EcdhIdentityKey.DeriveKeyPair("bob", "pw-b", FixedSalt, TestSpec);
        try
        {
            using var ecdhA = ECDiffieHellman.Create();
            ecdhA.ImportECPrivateKey(privA, out _);
            using var ecdhB = ECDiffieHellman.Create();
            ecdhB.ImportECPrivateKey(privB, out _);

            // 公開鍵 raw (0x04||X||Y) からの import（ECIES wrap 側の経路と同一）
            using var ecdhBFromRaw = ECDiffieHellman.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = ImportRawPublicKey(pubB),
            });

            byte[] shared1 = ecdhA.DeriveRawSecretAgreement(ecdhBFromRaw.PublicKey);
            byte[] shared2 = ecdhB.DeriveRawSecretAgreement(ecdhA.PublicKey);
            CryptographicOperations.ZeroMemory(shared1);
            CryptographicOperations.ZeroMemory(shared2);
            Assert.Equal(shared1, shared2);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privA);
            CryptographicOperations.ZeroMemory(privB);
        }
    }

    [Fact]
    public void GenerateIdentitySalt_Returns32RandomBytes()
    {
        byte[] s1 = EcdhIdentityKey.GenerateIdentitySalt();
        byte[] s2 = EcdhIdentityKey.GenerateIdentitySalt();
        Assert.Equal(32, s1.Length);
        Assert.NotEqual(s1, s2);
    }

    private static ECPoint ImportRawPublicKey(byte[] raw)
    {
        Assert.Equal(65, raw.Length);
        Assert.Equal(0x04, raw[0]);
        return new ECPoint
        {
            X = raw.AsSpan(1, 32).ToArray(),
            Y = raw.AsSpan(33, 32).ToArray(),
        };
    }
}

/// <summary>
/// 共有ポリシー（SharingPolicy / AccountService SharingEnabled）のテスト。
/// - 新規ユーザーは既定で SharingEnabled = true（既存ユーザー移行を含む）
/// - グローバル無効時はユーザー設定に関係なく全操作拒否
/// - ユーザー無効時はそのユーザーの送受信・ECDH セットアップを拒否
/// - 公開鍵の上書きは明示的 rotation を必須とする
/// </summary>
public class SharingPolicyTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly CistaNasOptions _options;

    public SharingPolicyTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _options = _sp.GetRequiredService<IOptions<CistaNasOptions>>().Value;
    }

    private AccountService Account => _sp.CreateAsyncScope().ServiceProvider.GetRequiredService<AccountService>();

    [Fact]
    public async Task NewUsers_DefaultToSharingEnabled()
    {
        var account = Account;
        await account.CreateUserAsync("alice", "password123", "user");
        Assert.True(await account.IsSharingEnabledAsync("alice"));
    }

    [Fact]
    public async Task SetSharingEnabled_TogglesAndFiltersUserList()
    {
        var account = Account;
        await account.CreateUserAsync("alice", "password123", "user");
        await account.CreateUserAsync("bob", "password123", "user");

        await account.SetSharingEnabledAsync("bob", false);
        Assert.False(await account.IsSharingEnabledAsync("bob"));
        Assert.True(await account.IsSharingEnabledAsync("alice"));

        // sharingOnly=true の一覧から除外される
        var shareable = await account.ListUserDtosAsync(includeRoles: false, sharingOnly: true);
        Assert.Contains(shareable, u => u.UserName == "alice");
        Assert.DoesNotContain(shareable, u => u.UserName == "bob");

        // 全件一覧には現れる（管理者用）+ フラグが入る
        var all = await account.ListUserDtosAsync(includeRoles: false);
        var bob = all.First(u => u.UserName == "bob");
        Assert.False(bob.SharingEnabled);
    }

    [Fact]
    public async Task SharingPolicy_GlobalDisabled_DeniesAllActions()
    {
        var account = Account;
        await account.CreateUserAsync("alice", "password123", "user");
        _options.Sharing.Enabled = false;
        var policy = new SharingPolicy(Options.Create(_options), account);

        Assert.False(await policy.IsAllowedAsync(SharingAction.Send, "alice"));
        Assert.False(await policy.IsAllowedAsync(SharingAction.Receive, "alice"));
        Assert.False(await policy.IsAllowedAsync(SharingAction.SetupEcdh, "alice"));
        Assert.False(policy.IsGlobalSharingEnabled);

        // 復元（他テストへの影響防止。options インスタンスはスコープ内共有）
        _options.Sharing.Enabled = true;
        Assert.True(await policy.IsAllowedAsync(SharingAction.Send, "alice"));
    }

    [Fact]
    public async Task SharingPolicy_UserDisabled_DeniesThatUserOnly()
    {
        var account = Account;
        await account.CreateUserAsync("alice", "password123", "user");
        await account.CreateUserAsync("bob", "password123", "user");
        await account.SetSharingEnabledAsync("bob", false);
        var policy = new SharingPolicy(Options.Create(_options), account);

        Assert.True(await policy.IsAllowedAsync(SharingAction.Send, "alice"));
        Assert.False(await policy.IsAllowedAsync(SharingAction.Send, "bob"));
        Assert.False(await policy.IsAllowedAsync(SharingAction.Receive, "bob"));
        Assert.False(await policy.IsAllowedAsync(SharingAction.SetupEcdh, "bob"));
    }

    [Fact]
    public async Task EcdhIdentity_SaltIsStableAndNeverRecreated()
    {
        var account = Account;
        await account.CreateUserAsync("alice", "password123", "user");

        var first = await account.GetOrCreateEcdhIdentityAsync("alice");
        var second = await account.GetOrCreateEcdhIdentityAsync("alice");
        Assert.Equal(first.IdentitySalt, second.IdentitySalt);
        Assert.Equal(EcdhIdentityKey.CurrentDerivationVersion, second.DerivationVersion);
        Assert.Equal(EcdhIdentityKey.IdentitySaltSize, first.IdentitySalt.Length);
    }

    [Fact]
    public async Task UpdatePublicKey_ExistingKey_RejectedWithoutExplicitRotation()
    {
        var account = Account;
        await account.CreateUserAsync("alice", "password123", "user");

        byte[] key1 = RandomNumberGenerator.GetBytes(65);
        byte[] key2 = RandomNumberGenerator.GetBytes(65);
        string k1 = Convert.ToBase64String(key1);
        string k2 = Convert.ToBase64String(key2);

        await account.UpdatePublicKeyAsync("alice", k1);
        Assert.Equal(k1, await account.GetPublicKeyAsync("alice"));

        // 無断上書きは拒否（誤ったパスワードからの導出結果で identity を壊さない）
        await Assert.ThrowsAsync<InvalidOperationException>(() => account.UpdatePublicKeyAsync("alice", k2));
        Assert.Equal(k1, await account.GetPublicKeyAsync("alice"));

        // 同一鍵の再登録は冪等に成功
        await account.UpdatePublicKeyAsync("alice", k1);

        // 明示的 rotation のみ更新可
        await account.UpdatePublicKeyAsync("alice", k2, allowRotation: true);
        Assert.Equal(k2, await account.GetPublicKeyAsync("alice"));
    }

    public async ValueTask DisposeAsync()
    {
        try { if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true); } catch (Exception) { }
        await ValueTask.CompletedTask;
    }
}
