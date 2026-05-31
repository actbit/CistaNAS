using System.Security.Cryptography;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

/// <summary>
/// FileService のチャンク暗号化モードの統合テスト。
/// ChunkStorage = "auto" + Storage.Provider = "s3" でチャンクモードを強制。
/// </summary>
public class FileServiceChunkModeTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _vs;

    public FileServiceChunkModeTests()
    {
        (_sp, _dataRoot) = BuildChunkModeServices();
        _vs = _sp.GetRequiredService<VolumeService>();
    }

    private static (IServiceProvider sp, string dataRoot) BuildChunkModeServices()
    {
        var dataRoot = Path.Combine(Path.GetTempPath(), "cista-chunk-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataRoot);
        var opt = new CistaNasOptions
        {
            DataRoot = dataRoot,
            Storage = new StorageOptions { Provider = "s3" }, // チャンクモードを強制
            Volume = new VolumeOptions
            {
                SectorSize = 512,
                KdfIterations = 10_000,
                ChunkStorage = "auto",
                ServerChunkSize = 65536, // テスト用に小さめ（64KB）
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
        services.AddSingleton<IChunkStore>(sp =>
        {
            var storage = sp.GetRequiredService<IStorageProvider>();
            return new S3ChunkStore(storage);
        });
        services.AddSingleton(io);

        services.AddScoped<AccountService>();
        services.AddScoped<AuthService>();
        services.AddScoped<GroupService>();
        services.AddSingleton<InvitationService>();
        services.AddSingleton(new JwtSigningKey(new byte[32]));
        services.AddSingleton<VolumeMetadataStore>();
        services.AddSingleton<VolumeService>();
        services.AddScoped<JournalService>();
        services.AddScoped<FileService>();
        services.AddScoped<E2eeFileService>();
        services.AddLogging();

        var sp = services.BuildServiceProvider();
        using (var scope = sp.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Database.EnsureCreated();
        }
        return (sp, dataRoot);
    }

    private FileService GetFileService()
    {
        using var scope = _sp.CreateAsyncScope();
        return scope.ServiceProvider.GetRequiredService<FileService>();
    }

    private async Task<string> MountEncryptedVol(string name)
    {
        await _vs.CreateAsync(name, "testuser", "testpw", encrypted: true);
        return name;
    }

    [Fact]
    public async Task UploadDownload_ChunkMode_Roundtrip()
    {
        string vol = await MountEncryptedVol("chunk-rt");
        var fs = GetFileService();
        byte[] data = RandomNumberGenerator.GetBytes(10000);

        using (var ms = new MemoryStream(data))
            await fs.UploadAsync(vol, "test.bin", ms, data.Length);

        var dl = await fs.DownloadAsync(vol, "test.bin");
        using var dlStream = dl.Stream;
        Assert.True(dlStream.CanSeek, "チャンクモードのダウンロードストリームは Seek 可能であること");
        byte[] result = new byte[dl.Length];
        await dlStream.ReadExactlyAsync(result);
        Assert.Equal(data, result);
    }

    [Fact]
    public async Task UploadDownload_ChunkMode_LargeFile()
    {
        string vol = await MountEncryptedVol("chunk-large");
        var fs = GetFileService();
        // 64KB * 3 + 余り → 複数チャンク
        byte[] data = RandomNumberGenerator.GetBytes(65536 * 3 + 12345);

        using (var ms = new MemoryStream(data))
            await fs.UploadAsync(vol, "large.bin", ms, data.Length);

        var dl = await fs.DownloadAsync(vol, "large.bin");
        using var dlStream = dl.Stream;
        Assert.Equal(data.Length, dl.Length);

        byte[] result = new byte[data.Length];
        await dlStream.ReadExactlyAsync(result);
        Assert.Equal(data, result);
    }

    [Fact]
    public async Task Upload_ChunkMode_Overwrite()
    {
        string vol = await MountEncryptedVol("chunk-overwrite");
        var fs = GetFileService();

        byte[] data1 = RandomNumberGenerator.GetBytes(100000);
        using (var ms = new MemoryStream(data1))
            await fs.UploadAsync(vol, "file.bin", ms, data1.Length);

        byte[] data2 = RandomNumberGenerator.GetBytes(50000);
        using (var ms = new MemoryStream(data2))
            await fs.UploadAsync(vol, "file.bin", ms, data2.Length);

        var dl = await fs.DownloadAsync(vol, "file.bin");
        using var dlStream = dl.Stream;
        Assert.Equal(50000, dl.Length);
        byte[] result = new byte[50000];
        await dlStream.ReadExactlyAsync(result);
        Assert.Equal(data2, result);
    }

    [Fact]
    public async Task Delete_ChunkMode_CleansChunks()
    {
        string vol = await MountEncryptedVol("chunk-delete");
        var fs = GetFileService();
        var chunkStore = _sp.GetRequiredService<IChunkStore>();

        byte[] data = RandomNumberGenerator.GetBytes(100000);
        using (var ms = new MemoryStream(data))
            await fs.UploadAsync(vol, "todelete.bin", ms, data.Length);

        // チャンクが存在することを確認
        var chunksBefore = await chunkStore.ListChunksAsync(vol, "todelete.bin");
        Assert.NotEmpty(chunksBefore);

        await fs.DeleteAsync(vol, "todelete.bin");

        // チャンクが削除されていること
        var chunksAfter = await chunkStore.ListChunksAsync(vol, "todelete.bin");
        Assert.Empty(chunksAfter);
    }

    [Fact]
    public async Task Download_ChunkMode_SeekableStream()
    {
        string vol = await MountEncryptedVol("chunk-seek");
        var fs = GetFileService();
        byte[] data = RandomNumberGenerator.GetBytes(65536 * 2);

        using (var ms = new MemoryStream(data))
            await fs.UploadAsync(vol, "seekable.bin", ms, data.Length);

        var dl = await fs.DownloadAsync(vol, "seekable.bin");
        using var stream = dl.Stream;

        Assert.True(stream.CanSeek);
        Assert.Equal(data.Length, stream.Length);

        // Seek + Read の動作確認
        stream.Seek(50000, SeekOrigin.Begin);
        byte[] partial = new byte[1000];
        stream.ReadExactly(partial);
        byte[] expected = data[50000..51000];
        Assert.Equal(expected, partial);

        // End からの Seek
        stream.Seek(-500, SeekOrigin.End);
        byte[] tail = new byte[500];
        stream.ReadExactly(tail);
        Assert.Equal(data[^500..], tail);
    }

    [Fact]
    public async Task UploadDownload_ChunkMode_EmptyFile()
    {
        string vol = await MountEncryptedVol("chunk-empty");
        var fs = GetFileService();

        // 0 バイトファイルのアップロード
        using (var ms = new MemoryStream())
            await fs.UploadAsync(vol, "empty.bin", ms, 0);

        var dl = await fs.DownloadAsync(vol, "empty.bin");
        using var dlStream = dl.Stream;
        Assert.Equal(0, dl.Length);

        byte[] buf = new byte[1];
        int n = dlStream.Read(buf, 0, 1);
        Assert.Equal(0, n);
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
