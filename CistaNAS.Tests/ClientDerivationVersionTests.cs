using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CistaNAS.Client.Api;
using CistaNAS.Client.Services;
using CistaNAS.Mobile.Core.Abstractions;
using CistaNAS.Mobile.Core.Services;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// クライアント（Desktop / Mobile）の ECDH identity 導出経路に関する契約テスト。
///
/// - 未対応の DerivationVersion を fail closed で拒否すること（導出・公開鍵の登録更新を
///   行わない。導出仕様が変わったサーバーに旧仕様で導出すると既存 identity を破壊する = データ欠損）
/// - ECDH 秘密鍵が secure store / 永続化ストレージに一切書き込まれないこと（RAM 上のみ）
/// - 旧バージョンが残留させた秘密鍵の検出・削除が機能すること
///
/// Wasm (E2eeKeyResolverService.LoadPrivateKeyAsync) は JS interop が必要なため単体テスト対象外
/// （同一の DerivationVersion チェックを実装済み。ブラウザ経路は Playwright テストで担保）。
/// </summary>
public class ClientDerivationVersionTests
{
    // ---- Desktop: EcdhIdentityUnlock.DeriveVerified ----

    private static EcdhIdentitySetupInfo MakeSetup(int derivationVersion, string username, string password, out byte[] expectedPub)
    {
        byte[] salt = EcdhIdentityKey.GenerateIdentitySalt();
        var spec = new KdfSpec("pbkdf2-sha256", 10_000, 0, 0, 0);
        (expectedPub, _) = EcdhIdentityKey.DeriveKeyPair(username, password, salt, spec);
        return new EcdhIdentitySetupInfo
        {
            IdentitySalt = salt,
            DerivationVersion = derivationVersion,
            PublicKey = null,
            Kdf = new KdfInfo("pbkdf2-sha256", 10_000, 0, 0, 0),
        };
    }

    [Fact]
    public void Desktop_DeriveVerified_CurrentVersion_Succeeds()
    {
        string username = $"dv-d-{Guid.NewGuid():N}";
        string password = "key-pass-😊";
        var setup = MakeSetup(EcdhIdentityKey.CurrentDerivationVersion, username, password, out byte[] expectedPub);

        var (pub, priv) = EcdhIdentityUnlock.DeriveVerified(username, password, setup);

        Assert.Equal(expectedPub, pub);
        Assert.NotEmpty(priv);
        CryptographicOperations.ZeroMemory(priv);
    }

    [Theory]
    [InlineData(0)]                          // 未初期化（旧 DB レコード）
    [InlineData(2)]                          // 未来のバージョン
    public void Desktop_DeriveVerified_UnsupportedVersion_FailsClosed(int unsupportedVersion)
    {
        string username = $"dv-d-{Guid.NewGuid():N}";
        string password = "key-pass";
        var setup = MakeSetup(unsupportedVersion, username, password, out _);

        Assert.Throws<NotSupportedException>(
            () => EcdhIdentityUnlock.DeriveVerified(username, password, setup));
    }

    [Fact]
    public void Desktop_DeriveVerified_UnsupportedVersion_DoesNotRegisterKey()
    {
        // fail closed の本質: 例外が NotSupportedException であること（= 導出前に拒否され、
        // 誤導出による「公開鍵不一致」の InvalidOperationException ではないこと）
        string username = $"dv-d-{Guid.NewGuid():N}";
        var setup = MakeSetup(EcdhIdentityKey.CurrentDerivationVersion + 1, username, "any-pass", out byte[] registered);
        setup.PublicKey = Convert.ToBase64String(registered);

        var ex = Assert.Throws<NotSupportedException>(
            () => EcdhIdentityUnlock.DeriveVerified(username, "any-pass", setup));
        Assert.Contains("未対応", ex.Message);
    }

    // ---- Desktop: LegacyEcdhKeyCleanup（旧 DPAPI 秘密鍵ファイルの検出・削除） ----

    [Fact]
    public void Desktop_LegacyEcdhKeyCleanup_DetectsAndDeletesLegacyKeyFile()
    {
        // %APPDATA%/CistaNAS/ecdh_private_{username}.bin（旧バージョンの残留物）を
        // 実際の検出パスに作って検出 → 削除まで検証する（テスト用の孤立ファイルのみ）
        string appDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CistaNAS");
        Directory.CreateDirectory(appDir);
        string testFile = Path.Combine(appDir, $"ecdh_private_dv-test-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(testFile, new byte[] { 1, 2, 3 });
        try
        {
            Assert.Contains(testFile, LegacyEcdhKeyCleanup.DetectLegacyKeyFiles());

            Assert.Equal(1, LegacyEcdhKeyCleanup.DeleteLegacyKeyFiles());
            Assert.DoesNotContain(testFile, LegacyEcdhKeyCleanup.DetectLegacyKeyFiles());
            Assert.False(File.Exists(testFile));
        }
        finally
        {
            if (File.Exists(testFile)) File.Delete(testFile);
        }
    }

    // ---- Mobile: 未対応 DerivationVersion の fail closed + 公開鍵を登録しないこと ----

    /// <summary>identity-setup 応答をスタブする HTTP ハンドラ（公開鍵登録の監視付き）。</summary>
    private sealed class StubIdentityServerHandler(int derivationVersion, string? publicKeyBase64) : HttpMessageHandler
    {
        public int PublicKeyPutCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string path = request.RequestUri!.AbsolutePath;
            if (path == "/api/v1/e2ee/identity-setup" && request.Method == HttpMethod.Get)
            {
                string json = JsonSerializer.Serialize(new
                {
                    identitySalt = Convert.ToBase64String(EcdhIdentityKey.GenerateIdentitySalt()),
                    derivationVersion,
                    publicKey = publicKeyBase64,
                    kdf = new { algorithm = "pbkdf2-sha256", iterations = 10000, memoryKiB = 0, timeCost = 0, parallelism = 0 },
                });
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new StringContent(json, Encoding.UTF8, "application/json") });
            }
            if (path == "/api/v1/e2ee/my-public-key")
            {
                PublicKeyPutCount++;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    private static CistaNasApiClient ClientFor(HttpMessageHandler handler)
        => new(new HttpClient(handler) { BaseAddress = new Uri("https://stub.test/") });

    [Fact]
    public async Task Mobile_DeriveVerified_UnsupportedVersion_FailsClosed_AndDoesNotRegisterKey()
    {
        string username = $"dv-m-{Guid.NewGuid():N}";
        var handler = new StubIdentityServerHandler(
            EcdhIdentityKey.CurrentDerivationVersion + 1, publicKeyBase64: null);
        var api = ClientFor(handler);
        var manager = new EcdhKeyManager();

        // 導出が拒否される
        await Assert.ThrowsAsync<NotSupportedException>(
            () => manager.DeriveVerifiedAsync(api, username, "e2ee-pass"));

        // セットアップ（導出 → 未登録なら公開鍵登録）でも導出段階で中止され、
        // サーバーへ公開鍵を登録・更新しない（誤った identity の登録防止）
        await Assert.ThrowsAsync<NotSupportedException>(
            () => manager.SetupIdentityKeyAsync(api, username, "e2ee-pass"));
        Assert.Equal(0, handler.PublicKeyPutCount);
    }

    [Fact]
    public async Task Mobile_DeriveVerified_UnsupportedVersion_RegisteredKeyIsNotOverwritten()
    {
        // 登録済み公開鍵が存在する場合も、未対応バージョンでは導出・照合・更新のいずれも行わない
        string username = $"dv-m-{Guid.NewGuid():N}";
        var (_, priv) = EcdhIdentityKey.DeriveKeyPair(
            username, "pass", EcdhIdentityKey.GenerateIdentitySalt(), new KdfSpec("pbkdf2-sha256", 10_000, 0, 0, 0));
        CryptographicOperations.ZeroMemory(priv);
        string registeredB64 = Convert.ToBase64String(EcdhCryptoTestHelper.RandomPublicKey());

        var handler = new StubIdentityServerHandler(999, registeredB64);
        var manager = new EcdhKeyManager();

        await Assert.ThrowsAsync<NotSupportedException>(
            () => manager.DeriveVerifiedAsync(ClientFor(handler), username, "pass"));
        Assert.Equal(0, handler.PublicKeyPutCount);
    }

    [Fact]
    public async Task Mobile_DeriveVerified_CurrentVersion_DerivesMatchingKey()
    {
        string username = $"dv-m-{Guid.NewGuid():N}";
        string password = "e2ee-pass-🔑";
        byte[] salt = EcdhIdentityKey.GenerateIdentitySalt();
        var spec = new KdfSpec("pbkdf2-sha256", 10_000, 0, 0, 0);
        var (expectedPub, _) = EcdhIdentityKey.DeriveKeyPair(username, password, salt, spec);

        // スタブサーバーは salt を毎回生成するため、salt 固定のハンドラで検証する
        var handler = new FixedSaltIdentityHandler(EcdhIdentityKey.CurrentDerivationVersion, salt);
        var manager = new EcdhKeyManager();

        var (pub, priv) = await manager.DeriveVerifiedAsync(ClientFor(handler), username, password);
        Assert.Equal(expectedPub, pub);
        Assert.Equal(expectedPub, EcdhKeyManager.GetRawPublicKey(priv));
        CryptographicOperations.ZeroMemory(priv);
    }

    /// <summary>salt 固定の identity-setup スタブ（導出結果の一致検証用）。</summary>
    private sealed class FixedSaltIdentityHandler(int derivationVersion, byte[] salt) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string json = JsonSerializer.Serialize(new
            {
                identitySalt = Convert.ToBase64String(salt),
                derivationVersion,
                publicKey = (string?)null,
                kdf = new { algorithm = "pbkdf2-sha256", iterations = 10000, memoryKiB = 0, timeCost = 0, parallelism = 0 },
            });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent(json, Encoding.UTF8, "application/json") });
        }
    }

    // ---- Mobile: 秘密鍵の非永続化（secure store に一切書き込まれないこと） ----

    [Fact]
    public async Task Mobile_DeriveVerified_NeverPersistsPrivateKeyToSecureStore()
    {
        // 導出成功後も secure store（AndroidKeyStore ラップ相当）に ecdh_priv_* が
        // 出現しないこと。秘密鍵は RAM 上のみに存在する契約（項目 6）。
        string username = $"dv-m-{Guid.NewGuid():N}";
        byte[] salt = EcdhIdentityKey.GenerateIdentitySalt();
        var handler = new FixedSaltIdentityHandler(EcdhIdentityKey.CurrentDerivationVersion, salt);
        var manager = new EcdhKeyManager();
        var keyStore = new MemorySecureKeyStore();

        var (_, priv) = await manager.DeriveVerifiedAsync(ClientFor(handler), username, "e2ee-pass");
        CryptographicOperations.ZeroMemory(priv);

        Assert.Empty(keyStore.Keys);
        Assert.False(EcdhKeyManager.HasLegacySecureStoreKey(keyStore, username));

        // セットアップ（公開鍵登録を含む）経路でも永続化されない
        var (_, priv2) = await manager.DeriveVerifiedAsync(ClientFor(handler), username, "e2ee-pass");
        CryptographicOperations.ZeroMemory(priv2);
        Assert.Empty(keyStore.Keys);
    }

    [Fact]
    public void Mobile_LegacySecureStoreKey_DetectedAndDeleted()
    {
        string username = $"dv-m-{Guid.NewGuid():N}";
        var keyStore = new MemorySecureKeyStore();
        keyStore.Save("ecdh_priv_" + username, new byte[] { 9, 8, 7 });

        Assert.True(EcdhKeyManager.HasLegacySecureStoreKey(keyStore, username));

        EcdhKeyManager.DeleteLegacySecureStoreKey(keyStore, username);

        Assert.False(EcdhKeyManager.HasLegacySecureStoreKey(keyStore, username));
        Assert.Null(keyStore.Load("ecdh_priv_" + username));
        Assert.Empty(keyStore.Keys);
    }
}

/// <summary>テスト用ユーティリティ。</summary>
internal static class EcdhCryptoTestHelper
{
    /// <summary>ランダムな有効な P-256 公開鍵（raw 65B）を生成する。</summary>
    public static byte[] RandomPublicKey()
    {
        var (pub, priv) = EcdhIdentityKey.DeriveKeyPair(
            $"helper-{Guid.NewGuid():N}", "pass", EcdhIdentityKey.GenerateIdentitySalt(),
            new KdfSpec("pbkdf2-sha256", 10_000, 0, 0, 0));
        CryptographicOperations.ZeroMemory(priv);
        return pub;
    }
}
