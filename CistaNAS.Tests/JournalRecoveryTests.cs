using CistaNAS.Web.Journal;
using CistaNAS.Web.Services;
using Microsoft.Extensions.DependencyInjection;

namespace CistaNAS.Tests;

/// <summary>
/// ジャーナルクラッシュ復旧の統合テスト。
/// クラッシュ（未コミットジャーナル残留）をシミュレートし、
/// 再マウント時に FileService.RecoverAsync が走ってカタログを修復することを検証する。
/// </summary>
public class JournalRecoveryTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _vs;

    public JournalRecoveryTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _vs = _sp.GetRequiredService<VolumeService>();
    }

    private FileService GetFileService()
    {
        using var scope = _sp.CreateAsyncScope();
        return scope.ServiceProvider.GetRequiredService<FileService>();
    }

    private JournalService GetJournalService()
    {
        using var scope = _sp.CreateAsyncScope();
        return scope.ServiceProvider.GetRequiredService<JournalService>();
    }

    /// <summary>未コミットの DeleteFile ジャーナルが、再マウント時に復旧（カタログ反映＋ジャーナルクリア）される。</summary>
    [Fact]
    public async Task Remount_RecoversPendingDeleteJournal()
    {
        string vol = "recover-local";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: false);

        var fs = GetFileService();
        byte[] data = "x"u8.ToArray();
        using (var ms = new MemoryStream(data)) await fs.UploadAsync(vol, "a.txt", ms, 1);
        using (var ms = new MemoryStream(data)) await fs.UploadAsync(vol, "b.txt", ms, 1);

        // クラッシュシミュレート: b.txt の削除をジャーナルにだけ記録し、Commit しない
        // （FileService.DeleteAsync は RecordAsync → catalog.Remove → CommitAsync の順だが、
        //   RecordAsync 後・catalog.Remove 前にクラッシュした状態を再現）
        await GetJournalService().RecordAsync(vol, new JournalEntry
        {
            Operation = JournalOp.DeleteFile,
            Path = "b.txt",
        });

        // クラッシュ直後: カタログには a, b が残り、ジャーナルに b.txt 削除未コミット
        Assert.Equal(2, (await fs.ListAsync(vol)).Files.Count);
        Assert.True(await GetJournalService().HasPendingAsync(vol));

        // アンマウント → 再マウント（ここで RecoverAsync が走るべき）
        await _vs.LockAsync(vol, "testuser");
        await _vs.MountAsync(vol, "testuser", "testpw");

        // b.txt は復旧でカタログから削除されているべき
        var files = (await fs.ListAsync(vol)).Files.Select(f => f.Name).ToList();
        Assert.Single(files);
        Assert.Contains("a.txt", files);

        // ジャーナルはクリアされているべき
        Assert.False(await GetJournalService().HasPendingAsync(vol));
    }

    /// <summary>未コミットの WriteFile ジャーナル残留時、再マウントでジャーナルがクリアされる（肥大化防止）。</summary>
    [Fact]
    public async Task Remount_ClearsPendingWriteJournal()
    {
        string vol = "recover-write";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: false);

        var fs = GetFileService();
        byte[] data = "hello"u8.ToArray();
        using (var ms = new MemoryStream(data)) await fs.UploadAsync(vol, "keep.txt", ms, data.Length);

        // クラッシュシミュレート: WriteFile のジャーナルだけ記録（実際の書き込み未完了を模倣）
        await GetJournalService().RecordAsync(vol, new JournalEntry
        {
            Operation = JournalOp.WriteFile,
            Path = "unfinished.txt",
            Length = 100,
        });
        Assert.True(await GetJournalService().HasPendingAsync(vol));

        await _vs.LockAsync(vol, "testuser");
        await _vs.MountAsync(vol, "testuser", "testpw");

        // ジャーナルはクリアされるべき（再マウントで復旧完了扱い）
        Assert.False(await GetJournalService().HasPendingAsync(vol));
    }

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
