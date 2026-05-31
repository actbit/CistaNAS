using System.Security.Cryptography;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Identity;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

/// <summary>
/// FileService の並行アクセステスト。
/// ReaderWriterLockSlim による読み書き保護が正しく機能することを検証する。
/// </summary>
public class FileServiceConcurrencyTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _vs;

    public FileServiceConcurrencyTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _vs = _sp.GetRequiredService<VolumeService>();
    }

    private FileService GetFileService()
    {
        using var scope = _sp.CreateAsyncScope();
        return scope.ServiceProvider.GetRequiredService<FileService>();
    }

    private async Task<string> MountVol(string name)
    {
        await _vs.CreateAsync(name, "testuser", "testpw", encrypted: false);
        return name;
    }

    /// <summary>同じファイルの並行ダウンロードが全て正しいデータを返す。</summary>
    [Fact]
    public async Task ConcurrentDownloads_SameFile_AllGetCorrectData()
    {
        string vol = await MountVol("conc-dl-same");
        var fs = GetFileService();
        byte[] data = RandomNumberGenerator.GetBytes(5000);

        using (var ms = new MemoryStream(data))
            await fs.UploadAsync(vol, "shared.bin", ms, data.Length);

        // 5つの並行ダウンロード
        var tasks = Enumerable.Range(0, 5).Select(async _ =>
        {
            var fs2 = GetFileService();
            var dl = await fs2.DownloadAsync(vol, "shared.bin");
            using var stream = dl.Stream;
            byte[] result = new byte[dl.Length];
            await stream.ReadExactlyAsync(result);
            return result;
        }).ToArray();

        var results = await Task.WhenAll(tasks);

        foreach (var result in results)
            Assert.Equal(data, result);
    }

    /// <summary>異なるファイルの並行ダウンロードが独立して動作する。</summary>
    [Fact]
    public async Task ConcurrentDownloads_DifferentFiles_Independent()
    {
        string vol = await MountVol("conc-dl-diff");
        var fs = GetFileService();
        byte[] dataA = RandomNumberGenerator.GetBytes(3000);
        byte[] dataB = RandomNumberGenerator.GetBytes(4000);

        using (var ms = new MemoryStream(dataA))
            await fs.UploadAsync(vol, "a.bin", ms, dataA.Length);
        using (var ms = new MemoryStream(dataB))
            await fs.UploadAsync(vol, "b.bin", ms, dataB.Length);

        var dlA = Task.Run(async () =>
        {
            var fs2 = GetFileService();
            var dl = await fs2.DownloadAsync(vol, "a.bin");
            using var stream = dl.Stream;
            byte[] result = new byte[dl.Length];
            await stream.ReadExactlyAsync(result);
            return result;
        });

        var dlB = Task.Run(async () =>
        {
            var fs2 = GetFileService();
            var dl = await fs2.DownloadAsync(vol, "b.bin");
            using var stream = dl.Stream;
            byte[] result = new byte[dl.Length];
            await stream.ReadExactlyAsync(result);
            return result;
        });

        var results = await Task.WhenAll(dlA, dlB);
        Assert.Equal(dataA, results[0]);
        Assert.Equal(dataB, results[1]);
    }

    /// <summary>ダウンロード中の上書きは、ダウンロード完了までブロックされる。</summary>
    [Fact]
    public async Task DownloadWhileUploadWaits_BlocksUntilDownloadComplete()
    {
        string vol = await MountVol("conc-race");
        var fs = GetFileService();
        byte[] originalData = RandomNumberGenerator.GetBytes(5000);

        using (var ms = new MemoryStream(originalData))
            await fs.UploadAsync(vol, "race.bin", ms, originalData.Length);

        // ダウンロード開始（ストリームを保持したまま読み取りを遅延）
        var fs1 = GetFileService();
        var dl = await fs1.DownloadAsync(vol, "race.bin");
        var dlStream = dl.Stream;

        // 最初の半分を読み取り
        byte[] firstHalf = new byte[2500];
        await dlStream.ReadExactlyAsync(firstHalf);
        Assert.Equal(originalData[..2500], firstHalf);

        // 上書きを別スレッドで開始（ダウンロード完了までブロックされるはず）
        byte[] newData = RandomNumberGenerator.GetBytes(6000);
        bool uploadCompleted = false;
        var uploadTask = Task.Run(async () =>
        {
            var fs2 = GetFileService();
            using var ms = new MemoryStream(newData);
            await fs2.UploadAsync(vol, "race.bin", ms, newData.Length);
            uploadCompleted = true;
        });

        // 少し待ってもアップロードはまだ完了していないはず
        await Task.Delay(200);
        Assert.False(uploadCompleted);

        // 残りのダウンロードを完了してストリームを解放
        byte[] secondHalf = new byte[2500];
        await dlStream.ReadExactlyAsync(secondHalf);
        Assert.Equal(originalData[2500..], secondHalf);
        dlStream.Dispose();

        // アップロードが完了するはず
        await uploadTask;
        Assert.True(uploadCompleted);

        // 上書き後のデータが新しいものになっている
        var fs3 = GetFileService();
        var dl2 = await fs3.DownloadAsync(vol, "race.bin");
        using var dl2Stream = dl2.Stream;
        Assert.Equal(newData.Length, dl2.Length);
        byte[] result = new byte[newData.Length];
        await dl2Stream.ReadExactlyAsync(result);
        Assert.Equal(newData, result);
    }

    /// <summary>ダウンロード中のファイル削除は、ダウンロード完了まで待機する。</summary>
    [Fact]
    public async Task DeleteWaitsForActiveDownload()
    {
        string vol = await MountVol("conc-del");
        var fs = GetFileService();
        byte[] data = RandomNumberGenerator.GetBytes(3000);

        using (var ms = new MemoryStream(data))
            await fs.UploadAsync(vol, "to-delete.bin", ms, data.Length);

        // ダウンロード開始
        var fs1 = GetFileService();
        var dl = await fs1.DownloadAsync(vol, "to-delete.bin");
        var dlStream = dl.Stream;

        // 少し読み取り
        byte[] partial = new byte[1000];
        await dlStream.ReadExactlyAsync(partial);
        Assert.Equal(data[..1000], partial);

        // 削除を別スレッドで開始（ダウンロード完了までブロック）
        bool deleteCompleted = false;
        var deleteTask = Task.Run(async () =>
        {
            var fs2 = GetFileService();
            await fs2.DeleteAsync(vol, "to-delete.bin");
            deleteCompleted = true;
        });

        await Task.Delay(200);
        Assert.False(deleteCompleted);

        // ダウンロード完了 → 削除が進行
        dlStream.Dispose();
        await deleteTask;
        Assert.True(deleteCompleted);

        // ファイルが削除されている
        var fs3 = GetFileService();
        await Assert.ThrowsAsync<FileServiceException>(() => fs3.DownloadAsync(vol, "to-delete.bin"));
    }

    /// <summary>アップロード中のダウンロードは書き込み完了までブロックされる。</summary>
    [Fact]
    public async Task DownloadDuringUpload_WaitsForUpload()
    {
        string vol = await MountVol("conc-upload-first");
        var fs = GetFileService();
        byte[] data = RandomNumberGenerator.GetBytes(2000);

        using (var ms = new MemoryStream(data))
            await fs.UploadAsync(vol, "file.bin", ms, data.Length);

        // 書き込みロックを取得してからアップロードを開始
        byte[] newData = RandomNumberGenerator.GetBytes(3000);
        var uploadTcs = new TaskCompletionSource();
        bool downloadStarted = false;

        var uploadTask = Task.Run(async () =>
        {
            var fs2 = GetFileService();
            using var ms = new MemoryStream(newData);
            // UploadAsync が rwLock.WriteLock を取得
            // カスタムストリームで意図的に遅延を入れる
            var slowStream = new SlowReadStream(newData, uploadTcs);
            await fs2.UploadAsync(vol, "file.bin", slowStream, newData.Length);
        });

        // アップロードがロックを取得するまで少し待つ
        await Task.Delay(300);

        // ダウンロードを試行（アップロード完了までブロック）
        var downloadTask = Task.Run(async () =>
        {
            downloadStarted = true;
            var fs3 = GetFileService();
            var dl = await fs3.DownloadAsync(vol, "file.bin");
            using var stream = dl.Stream;
            byte[] result = new byte[dl.Length];
            await stream.ReadExactlyAsync(result);
            return result;
        });

        await Task.Delay(200);
        // ダウンロードは開始できているが、まだ完了していないはず
        Assert.True(downloadStarted);

        // アップロードの遅延を解除
        uploadTcs.SetResult();

        // 両方完了
        await uploadTask;
        var dlResult = await downloadTask;

        // アップロード完了後のダウンロードは新しいデータを返す
        Assert.Equal(newData, dlResult);
    }

    /// <summary>チャンクモード: 同一ファイルの並行ダウンロード。</summary>
    [Fact]
    public async Task ChunkMode_ConcurrentDownloads_SameFile()
    {
        string dataRoot = Path.Combine(Path.GetTempPath(), "cista-conc-chunk-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataRoot);
        var opt = new CistaNasOptions
        {
            DataRoot = dataRoot,
            Storage = new StorageOptions { Provider = "s3" },
            Volume = new VolumeOptions
            {
                SectorSize = 512,
                KdfIterations = 10_000,
                ChunkStorage = "auto",
                ServerChunkSize = 65536,
            },
            Auth = new AuthOptions { Pbkdf2Iterations = 10_000 },
        };
        var io = Options.Create(opt);
        var services = new ServiceCollection();

        var dbPath = Path.Combine(dataRoot, "test.db");
        var connStr = $"Data Source={dbPath};Mode=ReadWriteCreate;Cache=Shared;Pooling=False";
        services.AddDbContext<AppDbContext>(o => o.UseSqlite(connStr));
        services.AddIdentity<ApplicationUser, ApplicationRole>(o =>
        {
            o.Password.RequiredLength = 4;
            o.Password.RequireNonAlphanumeric = false;
            o.Password.RequireUppercase = false;
            o.Password.RequireLowercase = false;
            o.Password.RequireDigit = false;
            o.Lockout.AllowedForNewUsers = false;
            o.Lockout.MaxFailedAccessAttempts = 99;
            o.User.RequireUniqueEmail = false;
        })
        .AddEntityFrameworkStores<AppDbContext>()
        .AddDefaultTokenProviders();
        services.AddScoped<IPasswordHasher<ApplicationUser>, LegacyPasswordHasher>();
        services.AddSingleton<IStorageProvider>(sp =>
        {
            var o = sp.GetRequiredService<IOptions<CistaNasOptions>>().Value;
            return new LocalStorageProvider(o.DataRoot);
        });
        services.AddSingleton<IChunkStore, S3ChunkStore>();
        services.AddSingleton(io);
        services.AddScoped<AccountService>();
        services.AddScoped<AuthService>();
        services.AddSingleton<InvitationService>();
        services.AddSingleton(new JwtSigningKey(new byte[32]));
        services.AddSingleton<VolumeMetadataStore>();
        services.AddSingleton<VolumeService>();
        services.AddScoped<JournalService>();
        services.AddScoped<FileService>();
        services.AddLogging();

        var sp = services.BuildServiceProvider();
        using (var scope = sp.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Database.EnsureCreated();
        }

        var vs = sp.GetRequiredService<VolumeService>();
        await vs.CreateAsync("chunk-conc", "testuser", "testpw", encrypted: true);

        using var scope2 = sp.CreateAsyncScope();
        var fs = scope2.ServiceProvider.GetRequiredService<FileService>();
        byte[] data = RandomNumberGenerator.GetBytes(65536 * 2 + 1234);

        using (var ms = new MemoryStream(data))
            await fs.UploadAsync("chunk-conc", "shared.bin", ms, data.Length);

        // 3つの並行ダウンロード
        var tasks = Enumerable.Range(0, 3).Select(async _ =>
        {
            using var s = sp.CreateAsyncScope();
            var fs2 = s.ServiceProvider.GetRequiredService<FileService>();
            var dl = await fs2.DownloadAsync("chunk-conc", "shared.bin");
            using var stream = dl.Stream;
            byte[] result = new byte[dl.Length];
            await stream.ReadExactlyAsync(result);
            return result;
        }).ToArray();

        var results = await Task.WhenAll(tasks);
        foreach (var result in results)
            Assert.Equal(data, result);

        // クリーンアップ
        try
        {
            var header = await vs.GetVolumeHeaderAsync("chunk-conc");
            await vs.LockAsync("chunk-conc", header.OwnerUser);
        }
        catch { }
        try { if (Directory.Exists(dataRoot)) Directory.Delete(dataRoot, true); } catch { }
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

    /// <summary>意図的に遅延を発生させる Stream。並行テストでタイミングを制御するために使用。</summary>
    private sealed class SlowReadStream(byte[] data, TaskCompletionSource tcs) : Stream
    {
        private int _position;
        private bool _released;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => data.Length;
        public override long Position { get => _position; set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!_released)
            {
                await tcs.Task;
                _released = true;
            }

            int remaining = data.Length - _position;
            if (remaining <= 0) return 0;

            int toRead = (int)Math.Min(buffer.Length, remaining);
            data.AsSpan(_position, toRead).CopyTo(buffer.Span);
            _position += toRead;
            return toRead;
        }

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
