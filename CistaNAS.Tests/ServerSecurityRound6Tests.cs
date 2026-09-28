using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

/// <summary>
/// サーバー側セキュリティレビュー round 6 の回帰テスト。
/// - [High] PATCH offset オーバーフローで OverflowException が 500 になる
/// - [High] E2EE create-file / upload-chunk がサイズ上限を持たない
/// - [High] 再ラップのフェーズ1保存後クラッシュで旧パスワードが有効のまま残留する
///   （マウント時の ClearStalePreviousWrap による掃除）
/// </summary>
public class ServerSecurityRound6Tests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _volumeService;
    private readonly byte[] _masterKey = RandomNumberGenerator.GetBytes(32);

    public ServerSecurityRound6Tests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _volumeService = _sp.GetRequiredService<VolumeService>();
    }

    // ---- [High] PATCH offset オーバーフロー ----

    [Fact]
    public async Task PATCHのoffsetオーバーフローはFileServiceExceptionになる()
    {
        // 回帰 (High): checked を挟む前は OverflowException が素通りし、
        // ハンドルされていない 500 になっていた。FileServiceException として拒否されるべき。
        var (sp, dataRoot) = TestHelper.BuildTestServices();
        try
        {
            await using var scope = sp.CreateAsyncScope();
            var vs = scope.ServiceProvider.GetRequiredService<VolumeService>();
            var fs = scope.ServiceProvider.GetRequiredService<FileService>();
            await vs.CreateAsync("of-vol", "testuser", "testpw", encrypted: false);

            byte[] data = new byte[16];
            // offset + contentLength が long.MaxValue を超える
            await Assert.ThrowsAsync<FileServiceException>(
                () => fs.PatchRangeAsync("of-vol", "of.bin", offset: long.MaxValue - 8,
                    new MemoryStream(data), contentLength: data.Length));
        }
        finally
        {
            if (sp is IAsyncDisposable dad) await dad.DisposeAsync();
            try { Directory.Delete(dataRoot, recursive: true); } catch { }
        }
    }

    // ---- [High] E2EE create-file / upload-chunk のサイズ上限 ----

    private async Task<(string Vol, E2eeFileService Fs, IServiceProvider Sp, string DataRoot)> BuildE2eeVolumeAsync(
        string name, VolumeOptions volOpts)
    {
        var (sp, dataRoot) = TestHelper.BuildTestServices(volOpts);
        await using var scope = sp.CreateAsyncScope();
        var vs = scope.ServiceProvider.GetRequiredService<VolumeService>();

        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek("testuser", "testpass", salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(_masterKey, kek);
        await vs.CreateE2eeAsync(name, "testuser", new VolumeHeader.UserWrappedKey
        {
            Kdf = new() { Algorithm = "pbkdf2-sha256", Iterations = 1000, Salt = salt },
            WrappedMasterKey = new()
            {
                Algorithm = "aes-256-gcm",
                Nonce = nonce,
                Ciphertext = ct,
                Tag = tag,
            },
        });

        var e2eeFs = new E2eeFileService(
            vs,
            sp.GetRequiredService<IStorageProvider>(),
            sp.GetRequiredService<IChunkStore>(),
            sp.GetRequiredService<IOptions<CistaNasOptions>>());
        return (name, e2eeFs, sp, dataRoot);
    }

    private static async Task DisposeServicesAsync(IServiceProvider sp, string dataRoot)
    {
        if (sp is IAsyncDisposable dad) await dad.DisposeAsync();
        try { Directory.Delete(dataRoot, recursive: true); } catch { }
    }

    [Fact]
    public async Task E2EE_CreateFileの平文サイズ超過は拒否される()
    {
        // 回帰 (High): FileService（plain PUT/PATCH）には MaxFileSizeBytes があったが、
        // E2EE CreateFile には無く、申告 EncryptedLength でディスクを予約させられた。
        var (vol, e2eeFs, sp, dataRoot) = await BuildE2eeVolumeAsync("cap-create",
            new VolumeOptions { MaxFileSizeBytes = 1500 });
        try
        {
            // chunk 1 個・平文 1000 バイト相当 → 上限内で成功
            long okEncrypted = E2eeFileService.SaltSize + 1000 + E2eeFileService.TagSize;
            var entry = await e2eeFs.CreateFileAsync(vol, new E2eeCreateFileRequest("ok", okEncrypted, 1), "testuser");
            Assert.False(string.IsNullOrEmpty(entry.FileId));

            // 平文 2000 バイト相当（chunk 2 個）→ 上限超過で拒否
            long overEncrypted = E2eeFileService.SaltSize + 2000 + 2 * E2eeFileService.TagSize;
            await Assert.ThrowsAsync<FileServiceException>(
                () => e2eeFs.CreateFileAsync(vol, new E2eeCreateFileRequest("over", overEncrypted, 2), "testuser"));
        }
        finally
        {
            await DisposeServicesAsync(sp, dataRoot);
        }
    }

    [Fact]
    public async Task E2EE_upload_chunkの末尾追記によるサイズ超過は拒否される()
    {
        // 回帰 (High): replace=true の chunkIndex == ChunkCount（末尾追記）に上限が無く、
        // チャンク追記の繰り返しで無制限にディスクを消費できた。
        var (vol, e2eeFs, sp, dataRoot) = await BuildE2eeVolumeAsync("cap-append",
            new VolumeOptions { MaxFileSizeBytes = 1500 });
        try
        {
            // 平文 1000 バイト（chunk 1 個）→ 上限 1500 内で作成
            long encLen = E2eeFileService.SaltSize + 1000 + E2eeFileService.TagSize;
            var entry = await e2eeFs.CreateFileAsync(vol, new E2eeCreateFileRequest("cap-file", encLen, 1), "testuser");

            byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
            byte[] fileKey = E2eeCrypto.DeriveFileKey(_masterKey, fileSalt);
            byte[] plain = RandomNumberGenerator.GetBytes(1000);

            byte[] enc0 = E2eeCrypto.EncryptChunk(plain, fileKey, 0, fileSalt, isFirstChunk: true);
            using (var ms0 = new MemoryStream(enc0))
                await e2eeFs.UploadChunkAsync(vol, entry.FileId, 0, ms0, enc0.Length);

            // 既存チャンクの同サイズ差分上書き → 投影サイズは変わらず成功
            byte[] enc0r = E2eeCrypto.EncryptChunk(plain, fileKey, 0, fileSalt, isFirstChunk: true, revision: 1);
            using (var ms0r = new MemoryStream(enc0r))
                await e2eeFs.UploadChunkAsync(vol, entry.FileId, 0, ms0r, enc0r.Length, replace: true);

            // 末尾追記（chunkIndex == ChunkCount == 1）→ 平文 2000 バイト > 上限 1500 で拒否
            byte[] enc1 = E2eeCrypto.EncryptChunk(plain, fileKey, 1, fileSalt, isFirstChunk: false);
            using (var ms1 = new MemoryStream(enc1))
                await Assert.ThrowsAsync<FileServiceException>(
                    () => e2eeFs.UploadChunkAsync(vol, entry.FileId, 1, ms1, enc1.Length, replace: true));
        }
        finally
        {
            await DisposeServicesAsync(sp, dataRoot);
        }
    }

    // ---- [High] クラッシュ残留 Previous ラップのマウント時掃除 ----

    [Fact]
    public async Task マウント成功時に残留した旧パスワードラップが撤去永続化される()
    {
        // 回帰 (High): RewrapAllForUserAsync のフェーズ1保存後にプロセスが落ちると、
        // ヘッダに Previous*（旧パスワードのラップ）が残留し、Identity 側の変更が
        // ロールバックされた場合に旧パスワードが永続的に有効だった。
        // 新実装はマウント成功（= 現行パスワードの証明）後に ClearStalePreviousWrap で撤去する。
        string vol = "stale-prev";
        await _volumeService.CreateAsync(vol, "testuser", "old-pw", encrypted: true);
        await _volumeService.LockAsync(vol, "testuser");

        // クラッシュ残留の再現: フェーズ1（旧ラップを Previous* に退避して新ラップを主に）
        // のみ行い保存したままコミットしない状態をヘッダに注入する。
        var metaStore = _sp.GetRequiredService<VolumeMetadataStore>();
        var header = await metaStore.LoadAsync(vol);
        Assert.NotNull(header);
        header!.BeginRewrapUser("testuser", "old-pw", "new-pw", new KdfSpec(KdfSpec.Argon2id, 10_000, 8192, 1, 1));
        await metaStore.SaveAsync(vol, header);

        // 旧パスワードでもアンラップできる（= 脆弱な状態）
        Assert.NotNull(header.UnwrapMasterKey("testuser", "old-pw"));

        // 現行（新）パスワードでのマウントに成功すると残留が掃除される
        await _volumeService.MountAsync(vol, "testuser", "new-pw");

        var reloaded = await metaStore.LoadAsync(vol);
        Assert.NotNull(reloaded);
        Assert.Null(reloaded!.UnwrapMasterKey("testuser", "old-pw"));
        Assert.NotNull(reloaded.UnwrapMasterKey("testuser", "new-pw"));
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var v in await _volumeService.ListAllAsync())
        {
            try
            {
                var header = await _volumeService.GetVolumeHeaderAsync(v.Name);
                await _volumeService.LockAsync(v.Name, header.OwnerUser);
            }
            catch (Exception) { }
        }
        try { if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true); } catch { }
    }
}
