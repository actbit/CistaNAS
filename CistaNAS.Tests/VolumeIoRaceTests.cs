using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using Microsoft.Extensions.DependencyInjection;

namespace CistaNAS.Tests;

/// <summary>
/// VolumeService のマウント/I/O 競合に関するテスト。
/// LockAsync / DeleteVolumeAsync 中の use-after-dispose レースが起きないこと、
/// 進行 I/O が安全に完了することを検証する。
/// </summary>
public class VolumeIoRaceTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _vs;

    public VolumeIoRaceTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _vs = _sp.GetRequiredService<VolumeService>();
    }

    /// <summary>
    /// アクティブ I/O がある間の LockAsync は I/O 完了を待機し、その間の新規 I/O を拒否する。
    /// I/O 完了後に安全に Stream を破棄する（破棄された Stream へのアクセス = use-after-dispose が起きない）。
    /// </summary>
    [Fact]
    public async Task LockAsync_WaitsForActiveIo_AndRejectsNewIoDuringUnmount()
    {
        string vol = "io-race";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: false);

        // アクティブ I/O を保持（IoTracker のカウント = 1）
        var (ioGuard, stream, _) = await _vs.GetMountedForIoAsync(vol);

        // LockAsync をバックグラウンドで開始（Close → TryRemove → WaitForZeroAsync で待機）
        var lockTask = Task.Run(() => _vs.LockAsync(vol, "testuser"));
        await Task.Delay(300); // アンマウント処理開始を待つ

        // アンマウント中: 新規 I/O は拒否される（破棄済み Stream を返さない）
        await Assert.ThrowsAsync<VolumeException>(() => _vs.GetMountedForIoAsync(vol));

        // 既存 I/O はまだ安全に使える（Stream は破棄されていない）
        Assert.True(stream.CanRead);

        // 既存 I/O を完了 → LockAsync が Stream を破棄して完了
        ioGuard.Dispose();
        await lockTask;

        Assert.False(_vs.IsMounted(vol));
    }

    /// <summary>進行 I/O がない場合、LockAsync は即座に Stream を破棄して完了する。</summary>
    [Fact]
    public async Task LockAsync_NoActiveIo_DisposesImmediately()
    {
        string vol = "io-noact";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: false);
        Assert.True(_vs.IsMounted(vol));

        await _vs.LockAsync(vol, "testuser");
        Assert.False(_vs.IsMounted(vol));
    }

    /// <summary>進行 I/O がある間の DeleteVolumeAsync は I/O 完了を待機する。</summary>
    [Fact]
    public async Task DeleteVolumeAsync_WaitsForActiveIo()
    {
        string vol = "io-delete";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: false);

        var (ioGuard, _, _) = await _vs.GetMountedForIoAsync(vol);

        var deleteTask = Task.Run(() => _vs.DeleteVolumeAsync(vol, "testuser"));
        await Task.Delay(300);

        // 進行 I/O がある間は削除完了しない
        Assert.False(deleteTask.IsCompleted);

        ioGuard.Dispose();
        await deleteTask;

        // ボリュームは削除済み
        Assert.Null(await _vs.GetVolumeInfoAsync(vol));
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
