using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Identity;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

/// <summary>
/// サーバー側セキュリティレビュー round 5 の回帰テスト。
/// - [Critical] ユーザー既定「サーバー暗号化」でボリュームが平文作成される
/// - [High] PATCH 巨大 offset によるディスク枯渇（サイズ上限の不在）
/// - [High] パスワード変更の途中失敗で KEK が分裂する（二相コミット再ラップ）
/// - [Medium] ユーザー削除での孤児ボリューム・最後の admin 削除
/// </summary>
public class ServerSecurityRound5Tests
{
    private static KdfSpec FastKdf => new(KdfSpec.Argon2id, 10_000, 8192, 1, 1);

    // ---- [Critical] 暗号化モード判定 ----

    [Theory]
    [InlineData(true, "server", true)]   // サーバー暗号化 → 暗号化される（回帰: false になっていた）
    [InlineData(true, "e2ee", true)]     // E2EE → ボリュームも暗号化
    [InlineData(true, "none", false)]    // 平文指定のみ平文
    [InlineData(true, null, true)]       // 未設定 → 既定 server 扱い
    [InlineData(true, "", true)]         // 空 → 既定 server 扱い
    [InlineData(false, "server", false)] // 非暗号化要求（home ボリューム等）は常に平文
    public void ResolveServerSideEncryption_はモード文字列を正しく解釈する(bool requested, string? mode, bool expected)
    {
        Assert.Equal(expected, VolumeService.ResolveServerSideEncryption(requested, mode));
    }

    [Fact]
    public async Task 既定サーバー暗号化ユーザーのボリュームは暗号化して作成される()
    {
        // 回帰 (Critical): ユーザー既定 "server" で encrypted=true でも
        // shouldEncrypt = mode != "server" の評価により false になり、
        // ヘッダ Encrypted=false・masterKey なしの平文 volume.dat が作成されていた。
        var (sp, dataRoot) = TestHelper.BuildTestServices();
        try
        {
            await using var scope = sp.CreateAsyncScope();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var account = scope.ServiceProvider.GetRequiredService<AccountService>();
            var vs = scope.ServiceProvider.GetRequiredService<VolumeService>();
            var metaStore = scope.ServiceProvider.GetRequiredService<VolumeMetadataStore>();

            await account.CreateUserAsync("encuser", "password");
            var user = await userManager.FindByNameAsync("encuser");
            Assert.NotNull(user);
            user!.DefaultEncryptionMode = "server"; // ApplicationUser の既定値（明示）
            await userManager.UpdateAsync(user);

            await vs.CreateAsync("enc-vol", "encuser", "password", encrypted: true);

            var header = await metaStore.LoadAsync("enc-vol");
            Assert.NotNull(header);
            Assert.True(header!.Encrypted, "「サーバー暗号化」ボリュームが平文で作成されました");
            Assert.NotNull(header.UnwrapMasterKey("encuser", "password"));
            Assert.Null(header.UnwrapMasterKey("encuser", "wrong"));
        }
        finally
        {
            await DisposeAsync(sp, dataRoot);
        }
    }

    [Fact]
    public async Task 既定noneユーザーのボリュームは平文で作成される()
    {
        var (sp, dataRoot) = TestHelper.BuildTestServices();
        try
        {
            await using var scope = sp.CreateAsyncScope();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var account = scope.ServiceProvider.GetRequiredService<AccountService>();
            var vs = scope.ServiceProvider.GetRequiredService<VolumeService>();
            var metaStore = scope.ServiceProvider.GetRequiredService<VolumeMetadataStore>();

            await account.CreateUserAsync("plainuser", "password");
            var user = await userManager.FindByNameAsync("plainuser");
            Assert.NotNull(user);
            user!.DefaultEncryptionMode = "none";
            await userManager.UpdateAsync(user);

            await vs.CreateAsync("plain-vol", "plainuser", "password", encrypted: true);

            var header = await metaStore.LoadAsync("plain-vol");
            Assert.NotNull(header);
            Assert.False(header!.Encrypted, "「平文」指定のボリュームが暗号化されました");
        }
        finally
        {
            await DisposeAsync(sp, dataRoot);
        }
    }

    // ---- [High] PATCH / UPLOAD のサイズ上限 ----

    [Fact]
    public async Task PATCHの巨大offsetはサイズ上限で拒否される()
    {
        // 回帰 (High): offset に上限がなく、新規ファイル + 巨大 offset で
        // sparse 埋め（82KB ずつの大量 I/O）によりディスクを枯渇させられた。
        var volOpts = new VolumeOptions
        {
            SectorSize = 512, KdfIterations = 10_000, KdfMemoryKiB = 8192, KdfTimeCost = 1, KdfParallelism = 1,
            MaxFileSizeBytes = 8192,
        };
        var (sp, dataRoot) = TestHelper.BuildTestServices(volOpts);
        try
        {
            await using var scope = sp.CreateAsyncScope();
            var vs = scope.ServiceProvider.GetRequiredService<VolumeService>();
            var fs = scope.ServiceProvider.GetRequiredService<FileService>();
            await vs.CreateAsync("limit-vol", "testuser", "testpw", encrypted: false);

            // Content-Length: 0 + 巨大 offset（DoS の再現シナリオ）
            await Assert.ThrowsAsync<FileServiceException>(
                () => fs.PatchRangeAsync("limit-vol", "evil.bin", offset: 1_000_000_000,
                    new MemoryStream(Array.Empty<byte>()), contentLength: 0));

            // 上限ギリギリは許可される
            byte[] data = new byte[4096];
            await fs.PatchRangeAsync("limit-vol", "ok.bin", offset: 4096, new MemoryStream(data), data.Length);
        }
        finally
        {
            await DisposeAsync(sp, dataRoot);
        }
    }

    [Fact]
    public async Task UPLOADのサイズ超過は拒否される()
    {
        var volOpts = new VolumeOptions
        {
            SectorSize = 512, KdfIterations = 10_000, KdfMemoryKiB = 8192, KdfTimeCost = 1, KdfParallelism = 1,
            MaxFileSizeBytes = 8192,
        };
        var (sp, dataRoot) = TestHelper.BuildTestServices(volOpts);
        try
        {
            await using var scope = sp.CreateAsyncScope();
            var vs = scope.ServiceProvider.GetRequiredService<VolumeService>();
            var fs = scope.ServiceProvider.GetRequiredService<FileService>();
            await vs.CreateAsync("limit-vol2", "testuser", "testpw", encrypted: false);

            byte[] big = new byte[16_000];
            await Assert.ThrowsAsync<FileServiceException>(
                () => fs.UploadAsync("limit-vol2", "big.bin", new MemoryStream(big), big.Length));
        }
        finally
        {
            await DisposeAsync(sp, dataRoot);
        }
    }

    // ---- [High] 二相コミット再ラップ ----

    private static (VolumeHeader Header, byte[] MasterKey) CreateHeader(string password)
    {
        byte[] master = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(master);
        var header = new VolumeHeader
        {
            Name = "t",
            CreatedAt = DateTimeOffset.UtcNow,
            Encrypted = true,
            SectorSize = 512,
            OwnerUser = "u",
        };
        header.AddUserWrap("u", password, master, FastKdf);
        return (header, master);
    }

    [Fact]
    public void 再ラップ準備中は旧パスワードと新パスワードの両方でアンラップできる()
    {
        var (header, master) = CreateHeader("old-password");

        header.BeginRewrapUser("u", "old-password", "new-password", FastKdf);

        // 新パスワードでも旧パスワードでも開ける（KEK 分裂しないことの核心）
        byte[]? withNew = header.UnwrapMasterKey("u", "new-password");
        byte[]? withOld = header.UnwrapMasterKey("u", "old-password");
        Assert.NotNull(withNew);
        Assert.NotNull(withOld);
        Assert.Equal(master, withNew);
        Assert.Equal(master, withOld);
    }

    [Fact]
    public void 再ラップ確定後は新パスワードのみで開ける()
    {
        var (header, _) = CreateHeader("old-password");
        header.BeginRewrapUser("u", "old-password", "new-password", FastKdf);

        header.CommitRewrapUser("u");

        Assert.NotNull(header.UnwrapMasterKey("u", "new-password"));
        Assert.Null(header.UnwrapMasterKey("u", "old-password"));
    }

    [Fact]
    public void 再ラップロールバックで旧パスワードのみに戻る()
    {
        var (header, _) = CreateHeader("old-password");
        header.BeginRewrapUser("u", "old-password", "new-password", FastKdf);

        header.RollbackRewrapUser("u");

        Assert.NotNull(header.UnwrapMasterKey("u", "old-password"));
        Assert.Null(header.UnwrapMasterKey("u", "new-password"));
    }

    [Fact]
    public void 準備中の二重ラップ状態はヘッダ永続化後も両パスワードで開ける()
    {
        // プロセス再起動（保存→読込）をまたいで旧ラップが生きていることを検証する。
        string path = Path.Combine(Path.GetTempPath(), $"cista-hdr-{Guid.NewGuid():N}.json");
        try
        {
            var (header, _) = CreateHeader("old-password");
            header.BeginRewrapUser("u", "old-password", "new-password", FastKdf);
            header.Save(path);

            var loaded = VolumeHeader.Load(path);
            Assert.NotNull(loaded.UnwrapMasterKey("u", "new-password"));
            Assert.NotNull(loaded.UnwrapMasterKey("u", "old-password"));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task RewrapAllForUserAsync_完了後は新パスワードでマウントできる()
    {
        var (sp, dataRoot) = TestHelper.BuildTestServices();
        try
        {
            await using var scope = sp.CreateAsyncScope();
            var vs = scope.ServiceProvider.GetRequiredService<VolumeService>();
            await vs.CreateAsync("rewrap-vol", "testuser", "old-pw", encrypted: true);
            await vs.LockAsync("rewrap-vol", "testuser"); // 一度ロックしてから検証する

            await vs.RewrapAllForUserAsync("testuser", "old-pw", "new-pw");

            // 新パスワードでマウント成功
            await vs.MountAsync("rewrap-vol", "testuser", "new-pw");
            // 旧パスワードは拒否
            await Assert.ThrowsAsync<VolumeException>(
                () => vs.MountAsync("rewrap-vol", "testuser", "old-pw"));
        }
        finally
        {
            await DisposeAsync(sp, dataRoot);
        }
    }

    // ---- [Medium] ユーザー削除の保護 ----

    [Fact]
    public async Task 最後の管理者は削除できない()
    {
        var (sp, dataRoot) = TestHelper.BuildTestServices();
        try
        {
            await using var scope = sp.CreateAsyncScope();
            var account = scope.ServiceProvider.GetRequiredService<AccountService>();
            await account.CreateUserAsync("sole-admin", "password", "admin");

            await Assert.ThrowsAsync<InvalidOperationException>(() => account.DeleteUserAsync("sole-admin"));
        }
        finally
        {
            await DisposeAsync(sp, dataRoot);
        }
    }

    [Fact]
    public async Task home以外の所有ボリュームがあるユーザーは削除できない()
    {
        var (sp, dataRoot) = TestHelper.BuildTestServices();
        try
        {
            await using var scope = sp.CreateAsyncScope();
            var account = scope.ServiceProvider.GetRequiredService<AccountService>();
            var vs = scope.ServiceProvider.GetRequiredService<VolumeService>();
            await account.CreateUserAsync("owner1", "password");
            await vs.CreateAsync("owned-vol", "owner1", "password", encrypted: false);

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => account.DeleteUserAsync("owner1"));
            Assert.Contains("owned-vol", ex.Message);
        }
        finally
        {
            await DisposeAsync(sp, dataRoot);
        }
    }

    private static async Task DisposeAsync(IServiceProvider sp, string dataRoot)
    {
        if (sp is IAsyncDisposable dad) await dad.DisposeAsync();
        try { Directory.Delete(dataRoot, recursive: true); } catch { }
    }
}
