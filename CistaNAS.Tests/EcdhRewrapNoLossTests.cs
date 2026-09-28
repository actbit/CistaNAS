using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Services;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;

namespace CistaNAS.Tests;

/// <summary>
/// login パスワード変更の KEK 再ラップと ECDH wrap の共存（データ欠損防止）。
/// - ECDH wrap（wrapType "ecdh"）は identity 公開鍵でラップされており login パスワードと無関係
///   （Kdf は "none"）。再ラップ対象外であること。誤って再ラップを試みると "none" の KDF 導出が
///   例外になり再ラップ全体が失敗 → ECDH 共有を受けたユーザーはパスワード変更できなくなる。
/// - パスワード wrap は変更後パスワードでのみアンラップ可能で、旧パスワードは失効すること。
/// </summary>
public class EcdhRewrapNoLossTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _vs;
    private const string MemberKeyPassword = "bob-key-pass";
    private static readonly KdfSpec FastSpec = new("pbkdf2-sha256", 10_000, 0, 0, 0);

    public EcdhRewrapNoLossTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _vs = _sp.GetRequiredService<VolumeService>();
    }

    // ---- パスワード変更フロー全体（ECDH wrap と password wrap の混在） ----

    [Fact]
    public async Task パスワード変更_ECDH共有の受領済みユーザーでも成功する()
    {
        // 回帰: BeginRewrapUser が ecdh エントリを再ラップしようとして "none" KDF で例外 →
        // 全ボリュームの再ラップが失敗し、ChangePasswordAsync がロールバックして常に false だった。
        var setup = await SetupMemberWithBothWrapTypesAsync();
        try
        {
            await using var scope = _sp.CreateAsyncScope();
            var account = scope.ServiceProvider.GetRequiredService<AccountService>();

            Assert.True(await account.ChangePasswordAsync("bob", "bob-old-pw", "bob-new-pw"),
                "ECDH wrap を持つユーザーのパスワード変更が失敗しました。");
        }
        finally
        {
            DisposeSetup(setup);
        }
    }

    [Fact]
    public async Task パスワード変更後_ECDHwrapは無変更でmasterKeyを復元できる()
    {
        // サーバーは ECDH wrap を一切触らない（identity 鍵由来のため login パスワード変更の影響を受けない）。
        var setup = await SetupMemberWithBothWrapTypesAsync();
        try
        {
            await using var scope = _sp.CreateAsyncScope();
            var account = scope.ServiceProvider.GetRequiredService<AccountService>();
            Assert.True(await account.ChangePasswordAsync("bob", "bob-old-pw", "bob-new-pw"));

            var header = await _vs.GetVolumeHeaderAsync(setup.SharedVol);
            var entry = header!.UserKeys["bob"];
            Assert.Equal("ecdh", entry.WrapType);
            Assert.Null(entry.PreviousKdf);
            Assert.Null(entry.PreviousWrappedMasterKey);

            byte[] unwrapped = E2eeCrypto.EcdhUnwrap(
                entry.WrappedMasterKey.Nonce,
                entry.WrappedMasterKey.Ciphertext,
                entry.WrappedMasterKey.Tag,
                entry.EphemeralPublicKey!, setup.PrivB);
            Assert.Equal(setup.MasterKeyB, unwrapped);
        }
        finally
        {
            DisposeSetup(setup);
        }
    }

    [Fact]
    public async Task パスワード変更後_passwordwrapは新パスワードでのみアンラップ可能()
    {
        var setup = await SetupMemberWithBothWrapTypesAsync();
        try
        {
            await using var scope = _sp.CreateAsyncScope();
            var account = scope.ServiceProvider.GetRequiredService<AccountService>();
            Assert.True(await account.ChangePasswordAsync("bob", "bob-old-pw", "bob-new-pw"));

            var header = await _vs.GetVolumeHeaderAsync(setup.PrivateVol);
            byte[]? withNew = header!.UnwrapMasterKey("bob", "bob-new-pw");
            byte[]? withOld = header.UnwrapMasterKey("bob", "bob-old-pw");
            try
            {
                Assert.NotNull(withNew);
                Assert.Equal(setup.MasterKeyPrivate, withNew);
                Assert.Null(withOld); // 旧パスワードは失効（KEK 分裂・残留がないこと）
                Assert.Null(header.UserKeys["bob"].PreviousKdf);
                Assert.Null(header.UserKeys["bob"].PreviousWrappedMasterKey);
            }
            finally
            {
                if (withNew is not null) CryptographicOperations.ZeroMemory(withNew);
            }
        }
        finally
        {
            DisposeSetup(setup);
        }
    }

    // ---- BeginRewrapUser の単体挙動 ----

    [Fact]
    public async Task BeginRewrapUser_ecdhエントリは無変更のnoOp()
    {
        var setup = await SetupMemberWithBothWrapTypesAsync();
        try
        {
            var header = await _vs.GetVolumeHeaderAsync(setup.SharedVol);
            var before = CloneEcdhEntry(header.UserKeys["bob"]);

            header.BeginRewrapUser(
                "bob", "any-old-pw", "any-new-pw", new KdfSpec(KdfSpec.Argon2id, 10_000, 8192, 1, 1));

            var entry = header.UserKeys["bob"];
            Assert.Equal(before.WrapType, entry.WrapType);
            Assert.Equal(before.Kdf.Algorithm, entry.Kdf.Algorithm);
            Assert.Equal(before.WrappedMasterKey.Ciphertext, entry.WrappedMasterKey.Ciphertext);
            Assert.Equal(before.WrappedMasterKey.Nonce, entry.WrappedMasterKey.Nonce);
            Assert.Equal(before.WrappedMasterKey.Tag, entry.WrappedMasterKey.Tag);
            Assert.Equal(before.EphemeralPublicKey, entry.EphemeralPublicKey);
            Assert.Null(entry.PreviousKdf);
            Assert.Null(entry.PreviousWrappedMasterKey);
        }
        finally
        {
            DisposeSetup(setup);
        }
    }

    // ---- 極端系: 連続変更・identity 不変性・クラッシュ窓・大量混在 ----

    [Fact]
    public async Task 二回連続のパスワード変更でも_ECDHwrapは1バイトも失われない()
    {
        var setup = await SetupMemberWithBothWrapTypesAsync();
        try
        {
            await using var scope = _sp.CreateAsyncScope();
            var account = scope.ServiceProvider.GetRequiredService<AccountService>();

            Assert.True(await account.ChangePasswordAsync("bob", "bob-old-pw", "bob-new-pw-1"));
            Assert.True(await account.ChangePasswordAsync("bob", "bob-new-pw-1", "bob-new-pw-2"));

            // ECDH wrap は毎回無変更 → 元の masterKey を連続で復元できる
            var header = await _vs.GetVolumeHeaderAsync(setup.SharedVol);
            var entry = header!.UserKeys["bob"];
            byte[] unwrapped = E2eeCrypto.EcdhUnwrap(
                entry.WrappedMasterKey.Nonce,
                entry.WrappedMasterKey.Ciphertext,
                entry.WrappedMasterKey.Tag,
                entry.EphemeralPublicKey!, setup.PrivB);
            Assert.Equal(setup.MasterKeyB, unwrapped);

            // password wrap も最終パスワードでのみ復元（旧2世代は完全失効、残留なし）
            var priv = await _vs.GetVolumeHeaderAsync(setup.PrivateVol);
            byte[]? withFinal = priv!.UnwrapMasterKey("bob", "bob-new-pw-2");
            try
            {
                Assert.Equal(setup.MasterKeyPrivate, withFinal);
                Assert.Null(priv.UnwrapMasterKey("bob", "bob-new-pw-1"));
                Assert.Null(priv.UnwrapMasterKey("bob", "bob-old-pw"));
                Assert.Null(priv.UserKeys["bob"].PreviousKdf);
                Assert.Null(priv.UserKeys["bob"].PreviousWrappedMasterKey);
            }
            finally
            {
                if (withFinal is not null) CryptographicOperations.ZeroMemory(withFinal);
            }
        }
        finally
        {
            DisposeSetup(setup);
        }
    }

    [Fact]
    public async Task パスワード変更は_identityのsaltとversionを不変に保つ()
    {
        // identity salt / version が変わると全ユーザーの導出鍵が変わり、
        // 存在する全 ECDH wrap が一斉に復号不能になる（共有データの総欠損）ため。
        var setup = await SetupMemberWithBothWrapTypesAsync();
        try
        {
            await using var scope = _sp.CreateAsyncScope();
            var account = scope.ServiceProvider.GetRequiredService<AccountService>();
            var before = await account.GetOrCreateEcdhIdentityAsync("bob");

            Assert.True(await account.ChangePasswordAsync("bob", "bob-old-pw", "bob-new-pw"));

            var after = await account.GetOrCreateEcdhIdentityAsync("bob");
            Assert.Equal(before.IdentitySalt, after.IdentitySalt);
            Assert.Equal(before.DerivationVersion, after.DerivationVersion);

            // 念のため ECDH wrap が実際に復元できることも確認
            var header = await _vs.GetVolumeHeaderAsync(setup.SharedVol);
            var entry = header!.UserKeys["bob"];
            byte[] unwrapped = E2eeCrypto.EcdhUnwrap(
                entry.WrappedMasterKey.Nonce,
                entry.WrappedMasterKey.Ciphertext,
                entry.WrappedMasterKey.Tag,
                entry.EphemeralPublicKey!, setup.PrivB);
            Assert.Equal(setup.MasterKeyB, unwrapped);
        }
        finally
        {
            DisposeSetup(setup);
        }
    }

    [Fact]
    public async Task BeginRewrap直後のクラッシュ窓でも新旧両パスワードでアンラップ可能()
    {
        // 第2相（Commit）前にプロセスが死んでも、Previous* 退避により旧パスワードでの
        // マウントが生きていること（KEK 分裂 = ボリューム喪失を防ぐ中核の保証）。
        var setup = await SetupMemberWithBothWrapTypesAsync();
        try
        {
            var header = await _vs.GetVolumeHeaderAsync(setup.PrivateVol);
            Assert.True(header!.Encrypted);

            header.BeginRewrapUser("bob", "bob-old-pw", "bob-crash-pw",
                new KdfSpec(KdfSpec.Argon2id, 10_000, 8192, 1, 1));

            // 新 wrap でも旧 wrap（Previous*）でも同一 masterKey が復元される
            byte[]? withNew = header.UnwrapMasterKey("bob", "bob-crash-pw");
            byte[]? withOld = header.UnwrapMasterKey("bob", "bob-old-pw");
            try
            {
                Assert.Equal(setup.MasterKeyPrivate, withNew);
                Assert.Equal(setup.MasterKeyPrivate, withOld);
            }
            finally
            {
                if (withNew is not null) CryptographicOperations.ZeroMemory(withNew);
                if (withOld is not null) CryptographicOperations.ZeroMemory(withOld);
            }

            // 第2相完了後は旧パスワードが失効する（窓が閉じ、残留もない）
            header.CommitRewrapUser("bob");
            byte[]? afterCommit = header.UnwrapMasterKey("bob", "bob-crash-pw");
            try
            {
                Assert.Equal(setup.MasterKeyPrivate, afterCommit);
                Assert.Null(header.UnwrapMasterKey("bob", "bob-old-pw"));
                Assert.Null(header.UserKeys["bob"].PreviousKdf);
                Assert.Null(header.UserKeys["bob"].PreviousWrappedMasterKey);
            }
            finally
            {
                if (afterCommit is not null) CryptographicOperations.ZeroMemory(afterCommit);
            }
        }
        finally
        {
            DisposeSetup(setup);
        }
    }

    [Fact]
    public async Task ECDHとpasswordの混在6ボリューム再ラップで_ECDHwrapは全てバイト等価()
    {
        // 大量混在でも 1 エントリも取りこぼさないこと（再ラップの網羅性 = 欠損ゼロの本体）
        var setup = await SetupMemberWithBothWrapTypesAsync();
        try
        {
            const int sharedCount = 3;
            var sharedVols = new string[sharedCount];
            var sharedKeys = new byte[sharedCount][];
            var ecdhBefore = new VolumeHeader.UserWrappedKey[sharedCount];

            sharedVols[0] = setup.SharedVol;
            sharedKeys[0] = setup.MasterKeyB;
            for (int i = 1; i < sharedCount; i++)
            {
                sharedVols[i] = $"rw-multi-{Guid.NewGuid():N}";
                sharedKeys[i] = await CreateVolumeWithEcdhMemberAsync(sharedVols[i]);
            }
            for (int i = 0; i < sharedCount; i++)
            {
                var h = await _vs.GetVolumeHeaderAsync(sharedVols[i]);
                ecdhBefore[i] = CloneEcdhEntry(h.UserKeys["bob"]);
            }

            await using (var scope = _sp.CreateAsyncScope())
            {
                var account = scope.ServiceProvider.GetRequiredService<AccountService>();
                Assert.True(await account.ChangePasswordAsync("bob", "bob-old-pw", "bob-multi-pw"));
            }

            for (int i = 0; i < sharedCount; i++)
            {
                var h = await _vs.GetVolumeHeaderAsync(sharedVols[i]);
                var entry = h.UserKeys["bob"];

                // ECDH wrap はバイト完全一致（ノンスも一時鍵も一切変わらない）
                Assert.Equal(ecdhBefore[i].WrappedMasterKey.Nonce, entry.WrappedMasterKey.Nonce);
                Assert.Equal(ecdhBefore[i].WrappedMasterKey.Ciphertext, entry.WrappedMasterKey.Ciphertext);
                Assert.Equal(ecdhBefore[i].WrappedMasterKey.Tag, entry.WrappedMasterKey.Tag);
                Assert.Equal(ecdhBefore[i].EphemeralPublicKey, entry.EphemeralPublicKey);
                Assert.Equal("ecdh", entry.WrapType);
                Assert.Null(entry.PreviousKdf);
                Assert.Null(entry.PreviousWrappedMasterKey);

                // 復元値も一致
                byte[] unwrapped = E2eeCrypto.EcdhUnwrap(
                    entry.WrappedMasterKey.Nonce,
                    entry.WrappedMasterKey.Ciphertext,
                    entry.WrappedMasterKey.Tag,
                    entry.EphemeralPublicKey!, setup.PrivB);
                Assert.Equal(sharedKeys[i], unwrapped);
            }

            // password wrap 側は新パスワードでのみ復元
            var priv = await _vs.GetVolumeHeaderAsync(setup.PrivateVol);
            byte[]? mk = priv!.UnwrapMasterKey("bob", "bob-multi-pw");
            try
            {
                Assert.Equal(setup.MasterKeyPrivate, mk);
                Assert.Null(priv.UnwrapMasterKey("bob", "bob-old-pw"));
            }
            finally
            {
                if (mk is not null) CryptographicOperations.ZeroMemory(mk);
            }
        }
        finally
        {
            DisposeSetup(setup);
        }
    }

    [Fact]
    public async Task ClearStalePreviousWrap_中断物を撤去すると旧パスワードは完全失効する()
    {
        // クラッシュ後に次回マウント認証が通った場合、Previous* は中断物として撤去される。
        // 撤去後は旧パスワードでの復号が不可能になる（巻き戻し攻撃の窓を確実に閉じる）。
        var setup = await SetupMemberWithBothWrapTypesAsync();
        try
        {
            var header = await _vs.GetVolumeHeaderAsync(setup.PrivateVol);

            header.BeginRewrapUser("bob", "bob-old-pw", "bob-crash-pw",
                new KdfSpec(KdfSpec.Argon2id, 10_000, 8192, 1, 1));

            // 中断物の撤去（マウント認証成功後に呼ぶ運用）
            Assert.True(header.ClearStalePreviousWrap("bob"));
            Assert.False(header.ClearStalePreviousWrap("bob")); // 二度目は noOp（冪等）

            // 新 wrap は有効、旧 wrap は参照先を失って完全失効
            byte[]? withNew = header.UnwrapMasterKey("bob", "bob-crash-pw");
            try
            {
                Assert.Equal(setup.MasterKeyPrivate, withNew);
                Assert.Null(header.UnwrapMasterKey("bob", "bob-old-pw"));
                Assert.Null(header.UserKeys["bob"].PreviousKdf);
                Assert.Null(header.UserKeys["bob"].PreviousWrappedMasterKey);
            }
            finally
            {
                if (withNew is not null) CryptographicOperations.ZeroMemory(withNew);
            }
        }
        finally
        {
            DisposeSetup(setup);
        }
    }

    [Fact]
    public async Task パスワードwrapを1つも持たない_ECDHのみのユーザーでもパスワード変更は成功する()
    {
        // 再ラップ対象が 0 件のユーザー（共有 only）。空ループのエッジで
        // 誤って例外や false を返すと、共有を受けたユーザーがパスワード変更できなくなる。
        await using var scope = _sp.CreateAsyncScope();
        var account = scope.ServiceProvider.GetRequiredService<AccountService>();
        await account.CreateUserAsync("eve", "eve-old-pw", "user");

        var identity = await account.GetOrCreateEcdhIdentityAsync("eve");
        var (pub, priv) = EcdhIdentityKey.DeriveKeyPair("eve", MemberKeyPassword, identity.IdentitySalt, FastSpec);
        try
        {
            await account.UpdatePublicKeyAsync("eve", Convert.ToBase64String(pub));

            // alice 所有ボリュームに eve 宛て ECDH wrap のみ（eve は password wrap を持たない）
            byte[] masterKey = E2eeCrypto.GenerateMasterKey();
            var (eph, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, pub);
            string vol = $"rw-eve-{Guid.NewGuid():N}";
            await _vs.CreateE2eeAsync(
                vol, "alice", CreatePasswordWrappedKey("alice", "alice-pw", E2eeCrypto.GenerateMasterKey()));
            await _vs.AddE2eeWrappedKeyAsync(vol, "alice", "eve", new VolumeHeader.UserWrappedKey
            {
                WrapType = "ecdh",
                Kdf = new() { Algorithm = "none" },
                WrappedMasterKey = new() { Algorithm = "aes-256-gcm", Nonce = nonce, Ciphertext = ct, Tag = tag },
                EphemeralPublicKey = eph,
            });

            // パスワード変更が成功し、ECDH wrap は無変更で復元できる
            Assert.True(await account.ChangePasswordAsync("eve", "eve-old-pw", "eve-new-pw"),
                "ECDH wrap のみのユーザーのパスワード変更が失敗しました。");
            var header = await _vs.GetVolumeHeaderAsync(vol);
            var entry = header.UserKeys["eve"];
            byte[] unwrapped = E2eeCrypto.EcdhUnwrap(
                entry.WrappedMasterKey.Nonce,
                entry.WrappedMasterKey.Ciphertext,
                entry.WrappedMasterKey.Tag,
                entry.EphemeralPublicKey!, priv);
            Assert.Equal(masterKey, unwrapped);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv);
        }
    }

    // ---- セットアップ ----

    private sealed record Setup(
        byte[] MasterKeyB, byte[] PrivB, byte[] MasterKeyPrivate, string SharedVol, string PrivateVol);

    private static void DisposeSetup(Setup setup)
    {
        CryptographicOperations.ZeroMemory(setup.PrivB);
    }

    /// <summary>
    /// bob を作成し、(1) alice 所有ボリュームの ECDH wrap（bob の identity 鍵でラップ）、
    /// (2) bob 自身の password wrap ボリューム、の両方を用意する。
    /// </summary>
    private async Task<Setup> SetupMemberWithBothWrapTypesAsync()
    {
        await using var scope = _sp.CreateAsyncScope();
        var account = scope.ServiceProvider.GetRequiredService<AccountService>();
        await account.CreateUserAsync("bob", "bob-old-pw", "user");

        // bob の identity 鍵を導出・登録（ECDH wrap の対象）
        var identity = await account.GetOrCreateEcdhIdentityAsync("bob");
        var (pub, priv) = EcdhIdentityKey.DeriveKeyPair("bob", MemberKeyPassword, identity.IdentitySalt, FastSpec);
        try
        {
            await account.UpdatePublicKeyAsync("bob", Convert.ToBase64String(pub));

            // (1) alice 所有ボリュームに bob 宛て ECDH wrap を追加
            string sharedVol = $"rw-shared-{Guid.NewGuid():N}";
            byte[] masterKeyB = await CreateVolumeWithEcdhMemberAsync(sharedVol);

            // (2) bob 自身の password wrap E2EE ボリューム
            string privateVol = $"rw-private-{Guid.NewGuid():N}";
            byte[] masterKeyPrivate = E2eeCrypto.GenerateMasterKey();
            await _vs.CreateE2eeAsync(privateVol, "bob", CreatePasswordWrappedKey("bob", "bob-old-pw", masterKeyPrivate));

            return new Setup(masterKeyB, priv, masterKeyPrivate, sharedVol, privateVol);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(priv);
            throw;
        }
    }

    /// <summary>alice 所有の E2EE ボリュームを作成し、bob の identity 公開鍵で ECDH wrap した鍵を追加する。</summary>
    private async Task<byte[]> CreateVolumeWithEcdhMemberAsync(string sharedVol)
    {
        await using var scope = _sp.CreateAsyncScope();
        var account = scope.ServiceProvider.GetRequiredService<AccountService>();
        var identity = await account.GetOrCreateEcdhIdentityAsync("bob");
        var (pub, _) = EcdhIdentityKey.DeriveKeyPair("bob", MemberKeyPassword, identity.IdentitySalt, FastSpec);

        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        var (eph, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, pub);

        await _vs.CreateE2eeAsync(
            sharedVol, "alice", CreatePasswordWrappedKey("alice", "alice-pw", E2eeCrypto.GenerateMasterKey()));
        await _vs.AddE2eeWrappedKeyAsync(sharedVol, "alice", "bob", new VolumeHeader.UserWrappedKey
        {
            WrapType = "ecdh",
            Kdf = new() { Algorithm = "none" },
            WrappedMasterKey = new() { Algorithm = "aes-256-gcm", Nonce = nonce, Ciphertext = ct, Tag = tag },
            EphemeralPublicKey = eph,
        });
        return masterKey;
    }

    private static VolumeHeader.UserWrappedKey CreatePasswordWrappedKey(string user, string password, byte[] masterKey)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(user, password, salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        return new VolumeHeader.UserWrappedKey
        {
            WrapType = "password",
            Kdf = new() { Algorithm = "pbkdf2-sha256", Iterations = 1000, Salt = salt },
            WrappedMasterKey = new() { Algorithm = "aes-256-gcm", Nonce = nonce, Ciphertext = ct, Tag = tag },
        };
    }

    private static VolumeHeader.UserWrappedKey CloneEcdhEntry(VolumeHeader.UserWrappedKey e) => new()
    {
        WrapType = e.WrapType,
        Kdf = new() { Algorithm = e.Kdf.Algorithm, Iterations = e.Kdf.Iterations, Salt = e.Kdf.Salt },
        WrappedMasterKey = new()
        {
            Algorithm = e.WrappedMasterKey.Algorithm,
            Nonce = e.WrappedMasterKey.Nonce,
            Ciphertext = e.WrappedMasterKey.Ciphertext,
            Tag = e.WrappedMasterKey.Tag,
        },
        EphemeralPublicKey = e.EphemeralPublicKey,
    };

    public async ValueTask DisposeAsync()
    {
        foreach (var v in await _vs.ListAllAsync())
        {
            try
            {
                var header = await _vs.GetVolumeHeaderAsync(v.Name);
                await _vs.LockAsync(v.Name, header.OwnerUser);
            }
            catch (Exception) { }
        }
        try { if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true); } catch (Exception) { }
    }
}
