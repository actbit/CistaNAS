using CistaNAS.Web.Journal;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using Microsoft.Extensions.DependencyInjection;

namespace CistaNAS.Tests;

/// <summary>
/// サーバー側暗号化ボリューム（XTS）の「通常フローでデータが一切欠損しないこと」の検証。
/// エッジケースではなく、 Everyday な操作系列 — 書き込み → アンマウント → 再マウント → 全量比較 —
/// を軸に、以下を保証する:
/// - ボリュームのマウントサイクルを跨いでも全ファイルがバイト等価で残る
/// - ファイル削除・部分書き込み（PatchRange）の後も他のデータが無傷
/// - パスワード変更（KEK 再ラップ）後もファイル内容がバイト等価で読める
/// - クラッシュ（未コミットジャーナル）後の再マウントで、コミット済みデータが無傷
/// </summary>
public class DataPersistenceNoLossTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _vs;

    public DataPersistenceNoLossTests()
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

    /// <summary>決定論的な疑似ランダムデータを生成する（テストの再実行性のため）。</summary>
    private static byte[] DeterministicBytes(int length, int seed)
    {
        var data = new byte[length];
        new Random(seed).NextBytes(data);
        return data;
    }

    private static async Task UploadAsync(FileService fs, string vol, string name, byte[] data)
    {
        using var ms = new MemoryStream(data);
        await fs.UploadAsync(vol, name, ms, data.Length);
    }

    private static async Task<byte[]> DownloadAllAsync(FileService fs, string vol, string name)
    {
        var dl = await fs.DownloadAsync(vol, name);
        using var dlStream = dl.Stream;
        var result = new byte[dl.Length];
        await dlStream.ReadExactlyAsync(result);
        return result;
    }

    /// <summary>複数サイズのファイルを書き込み、ボリュームのアンマウント → 再マウントを跨いでも
    /// 全ファイルがバイト等価で残ること（XTS ストリームの永続化）。</summary>
    [Fact]
    public async Task MultiFile_LockRemount_AllFilesByteIdentical()
    {
        string vol = "persist-multi";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: true);
        var fs = GetFileService();

        // 空ファイル / セクタ境界前後 / 複数セクタにまたがるサイズを含める
        var files = new Dictionary<string, byte[]>
        {
            ["empty.bin"] = [],
            ["tiny.bin"] = DeterministicBytes(1024, seed: 1),
            ["sector.bin"] = DeterministicBytes(4096, seed: 2),
            ["multi-sector.bin"] = DeterministicBytes(200_000, seed: 3),
        };
        foreach (var (name, data) in files)
            await UploadAsync(fs, vol, name, data);

        // アンマウント → 再マウント
        await _vs.LockAsync(vol, "testuser");
        await _vs.MountAsync(vol, "testuser", "testpw");

        foreach (var (name, data) in files)
        {
            byte[] actual = await DownloadAllAsync(fs, vol, name);
            Assert.Equal(data, actual);
        }
    }

    /// <summary>1 ファイル削除後、残りのファイルが再マウントを跨いでもバイト等価で残ること。</summary>
    [Fact]
    public async Task DeleteOneFile_Remount_SurvivorsByteIdentical()
    {
        string vol = "persist-delete";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: true);
        var fs = GetFileService();

        var survivors = new Dictionary<string, byte[]>
        {
            ["keep-a.bin"] = DeterministicBytes(50_000, seed: 11),
            ["keep-b.bin"] = DeterministicBytes(70_001, seed: 12),
        };
        byte[] doomed = DeterministicBytes(30_000, seed: 13);
        foreach (var (name, data) in survivors)
            await UploadAsync(fs, vol, name, data);
        await UploadAsync(fs, vol, "doomed.bin", doomed);

        await fs.DeleteAsync(vol, "doomed.bin");

        await _vs.LockAsync(vol, "testuser");
        await _vs.MountAsync(vol, "testuser", "testpw");

        var list = await fs.ListAsync(vol);
        Assert.Equal(2, list.Files.Count);
        foreach (var (name, data) in survivors)
        {
            byte[] actual = await DownloadAllAsync(fs, vol, name);
            Assert.Equal(data, actual);
        }
    }

    /// <summary>PatchRange で中間・末尾に書き込んだ内容が、再マウント後も保持されること
    /// （既存の FileServiceTests は直後の検証のみで、マウントサイクルを検証していなかった）。</summary>
    [Fact]
    public async Task PatchRange_ThenRemount_PreservedByteIdentical()
    {
        string vol = "persist-patch";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: true);
        var fs = GetFileService();

        byte[] initial = DeterministicBytes(64_000, seed: 21);
        await UploadAsync(fs, vol, "patched.bin", initial);

        // 中間（offset 12345）に 1000 バイト上書き
        byte[] patch = DeterministicBytes(1000, seed: 22);
        using (var pms = new MemoryStream(patch))
            await fs.PatchRangeAsync(vol, "patched.bin", 12345, pms, patch.Length);

        // 末尾に 5000 バイト追記（拡張）
        byte[] append = DeterministicBytes(5000, seed: 23);
        using (var ams = new MemoryStream(append))
            await fs.PatchRangeAsync(vol, "patched.bin", initial.Length, ams, append.Length);

        // 期待値を組み立て
        byte[] expected = new byte[initial.Length + append.Length];
        Array.Copy(initial, expected, initial.Length);
        Array.Copy(patch, 0, expected, 12345, patch.Length);
        Array.Copy(append, 0, expected, initial.Length, append.Length);

        await _vs.LockAsync(vol, "testuser");
        await _vs.MountAsync(vol, "testuser", "testpw");

        byte[] actual = await DownloadAllAsync(fs, vol, "patched.bin");
        Assert.Equal(expected, actual);
    }

    /// <summary>パスワード変更（KEK 再ラップ）後もファイル内容がバイト等価で読め、
    /// 旧パスワードは完全に失効すること（rewrap の内容レベル検証）。</summary>
    [Fact]
    public async Task RewrapPasswordChange_FilesByteIdentical_OldPasswordDead()
    {
        string vol = "persist-rewrap";
        await _vs.CreateAsync(vol, "testuser", "old-pw", encrypted: true);
        var fs = GetFileService();

        var files = new Dictionary<string, byte[]>
        {
            ["before-rewrap-1.bin"] = DeterministicBytes(33_333, seed: 31),
            ["before-rewrap-2.bin"] = DeterministicBytes(120_000, seed: 32),
        };
        foreach (var (name, data) in files)
            await UploadAsync(fs, vol, name, data);
        await _vs.LockAsync(vol, "testuser");

        // パスワード変更 → 全ボリュームの KEK 再ラップ
        await _vs.RewrapAllForUserAsync("testuser", "old-pw", "new-pw");

        // 旧パスワードは失効
        await Assert.ThrowsAsync<VolumeException>(() => _vs.MountAsync(vol, "testuser", "old-pw"));

        // 新パスワードでマウントでき、内容はバイト等価
        await _vs.MountAsync(vol, "testuser", "new-pw");
        foreach (var (name, data) in files)
        {
            byte[] actual = await DownloadAllAsync(fs, vol, name);
            Assert.Equal(data, actual);
        }
    }

    /// <summary>書き込み中のクラッシュ（未コミット WriteFile ジャーナル残留）後も、
    /// コミット済みファイルはバイト等価で無傷であり、ジャーナルは再マウントでクリアされる。</summary>
    [Fact]
    public async Task JournalCrash_PendingWrite_CommittedFilesIntactAfterRemount()
    {
        string vol = "persist-crash-write";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: true);
        var fs = GetFileService();

        var committed = new Dictionary<string, byte[]>
        {
            ["committed-a.bin"] = DeterministicBytes(40_000, seed: 41),
            ["committed-b.bin"] = DeterministicBytes(65_536, seed: 42),
        };
        foreach (var (name, data) in committed)
            await UploadAsync(fs, vol, name, data);

        // クラッシュシミュレート: 書き込み前のジャーナル記録だけが残り、Commit されない
        await GetJournalService().RecordAsync(vol, new JournalEntry
        {
            Operation = JournalOp.WriteFile,
            Path = "half-written.bin",
            Length = 999,
        });
        Assert.True(await GetJournalService().HasPendingAsync(vol));

        await _vs.LockAsync(vol, "testuser");
        await _vs.MountAsync(vol, "testuser", "testpw");

        // コミット済みデータは無傷
        foreach (var (name, data) in committed)
        {
            byte[] actual = await DownloadAllAsync(fs, vol, name);
            Assert.Equal(data, actual);
        }
        Assert.False(await GetJournalService().HasPendingAsync(vol));
    }

    /// <summary>削除中のクラッシュ（未コミット DeleteFile ジャーナル残留）後、
    /// 削除は復旧で反映され、それ以外のコミット済みデータはバイト等価で無傷。</summary>
    [Fact]
    public async Task JournalCrash_PendingDelete_DeletionApplied_OthersIntactAfterRemount()
    {
        string vol = "persist-crash-delete";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: true);
        var fs = GetFileService();

        byte[] victim = DeterministicBytes(20_000, seed: 51);
        var survivors = new Dictionary<string, byte[]>
        {
            ["survivor-a.bin"] = DeterministicBytes(45_000, seed: 52),
            ["survivor-b.bin"] = DeterministicBytes(10_000, seed: 53),
        };
        await UploadAsync(fs, vol, "victim.bin", victim);
        foreach (var (name, data) in survivors)
            await UploadAsync(fs, vol, name, data);

        // クラッシュシミュレート: victim.bin の削除をジャーナルにだけ記録
        await GetJournalService().RecordAsync(vol, new JournalEntry
        {
            Operation = JournalOp.DeleteFile,
            Path = "victim.bin",
        });

        await _vs.LockAsync(vol, "testuser");
        await _vs.MountAsync(vol, "testuser", "testpw");

        // victim.bin は復旧で削除され、他は無傷
        var names = (await fs.ListAsync(vol)).Files.Select(f => f.Name).ToList();
        Assert.DoesNotContain("victim.bin", names);
        Assert.Equal(2, names.Count);
        foreach (var (name, data) in survivors)
        {
            byte[] actual = await DownloadAllAsync(fs, vol, name);
            Assert.Equal(data, actual);
        }
        Assert.False(await GetJournalService().HasPendingAsync(vol));
    }

    /// <summary>1MiB ファイル（多数の XTS セクタにまたがる）が、マウントサイクルを跨いでバイト等価。</summary>
    [Fact]
    public async Task OneMiB_File_RoundtripByteIdentical_AcrossRemount()
    {
        string vol = "persist-1mib";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: true);
        var fs = GetFileService();

        byte[] data = DeterministicBytes(1024 * 1024, seed: 61);
        await UploadAsync(fs, vol, "large.bin", data);

        await _vs.LockAsync(vol, "testuser");
        await _vs.MountAsync(vol, "testuser", "testpw");

        byte[] actual = await DownloadAllAsync(fs, vol, "large.bin");
        Assert.Equal(data, actual);
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
