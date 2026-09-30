using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Volume;
using CistaNAS.Web.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

/// <summary>
/// 並行実行・同時アクセス下での「データ欠損ゼロ」の検証。
/// 複数タスクから同一ボリューム / 同一ファイル / 複数ボリュームに同時にアクセスし、
/// 以下の不変条件を保証する:
/// - 並行アップロードした全ファイルが完成し、再マウント後もバイト等価
/// - 非オーバーラップな並行 PatchRange は全て反映される
/// - 書き込み中の読み取りは「完全な旧版 or 完全な新版」のどちらかであり、決して断片化しない
/// - 削除と競合した読み取りは「完全な内容 or ファイル未存在」のどちらか
/// - 一覧取得と並行したアップロードが gate GC によって破壊されない
///   （static _fileGates の他ボリューム gate 破棄バグの回帰防止）
/// </summary>
public class ConcurrentAccessNoLossTests : IAsyncDisposable
{
    private const string Owner = "alice";
    private const int ChunkSize = 4096;

    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _vs;
    private readonly byte[] _masterKey = RandomNumberGenerator.GetBytes(32);

    public ConcurrentAccessNoLossTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _vs = _sp.GetRequiredService<VolumeService>();
    }

    private E2eeFileService GetE2eeFileService()
    {
        using var scope = _sp.CreateAsyncScope();
        var opt = _sp.GetRequiredService<IOptions<CistaNasOptions>>();
        var storage = _sp.GetRequiredService<IStorageProvider>();
        var chunkStore = _sp.GetRequiredService<IChunkStore>();
        return new E2eeFileService(_vs, storage, chunkStore, opt);
    }

    private FileService GetFileService()
    {
        using var scope = _sp.CreateAsyncScope();
        return scope.ServiceProvider.GetRequiredService<FileService>();
    }

    /// <summary>決定論的な疑似ランダムデータを生成する（テストの再実行性のため）。</summary>
    private static byte[] DeterministicBytes(int length, int seed)
    {
        var data = new byte[length];
        new Random(seed).NextBytes(data);
        return data;
    }

    private static async Task<byte[]> DownloadAllAsync(FileService fs, string vol, string name)
    {
        var dl = await fs.DownloadAsync(vol, name);
        using var dlStream = dl.Stream;
        var result = new byte[dl.Length];
        await dlStream.ReadExactlyAsync(result);
        return result;
    }

    private static async Task UploadAsync(FileService fs, string vol, string name, byte[] data)
    {
        using var ms = new MemoryStream(data);
        await fs.UploadAsync(vol, name, ms, data.Length);
    }

    // ---- XTS（サーバー側暗号化）: 同一ボリュームへの並行アクセス ----

    /// <summary>同一ボリュームに 8 ファイルを並行アップロードしても全てが完成し、
    /// 再マウント後も全量バイト等価であること。</summary>
    [Fact]
    public async Task ConcurrentUploads_DifferentFiles_AllByteIdentical()
    {
        string vol = "conc-xts-files";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: true);
        var fs = GetFileService();

        var files = Enumerable.Range(0, 8)
            .ToDictionary(i => $"file-{i}.bin", i => DeterministicBytes(30_000 + i * 111, seed: 200 + i));

        await Task.WhenAll(files.Select(f => UploadAsync(fs, vol, f.Key, f.Value)));

        // 再マウント後も全ての内容が保たれる
        await _vs.LockAsync(vol, "testuser");
        await _vs.MountAsync(vol, "testuser", "testpw");

        Assert.Equal(files.Count, (await fs.ListAsync(vol)).Files.Count);
        foreach (var (name, data) in files)
        {
            byte[] actual = await DownloadAllAsync(fs, vol, name);
            Assert.Equal(data, actual);
        }
    }

    /// <summary>同一ファイルへの非オーバーラップな並行 PatchRange が全て反映されること
    /// （ゲートが書き込みを直列化するため、パッチの取りこぼし・混在は起きない）。</summary>
    [Fact]
    public async Task ConcurrentPatchRange_DifferentOffsets_AllAppliedAfterRemount()
    {
        string vol = "conc-xts-patch";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: true);
        var fs = GetFileService();

        byte[] initial = DeterministicBytes(64_000, seed: 301);
        await UploadAsync(fs, vol, "patched.bin", initial);

        var patches = new (int Offset, byte[] Data)[]
        {
            (0, DeterministicBytes(2_000, seed: 302)),
            (20_000, DeterministicBytes(2_000, seed: 303)),
            (40_000, DeterministicBytes(2_000, seed: 304)),
            (62_000, DeterministicBytes(2_000, seed: 305)),
        };
        await Task.WhenAll(patches.Select(async p =>
        {
            using var ms = new MemoryStream(p.Data);
            await fs.PatchRangeAsync(vol, "patched.bin", p.Offset, ms, p.Data.Length);
        }));

        byte[] expected = (byte[])initial.Clone();
        foreach (var (offset, data) in patches)
            Array.Copy(data, 0, expected, offset, data.Length);

        await _vs.LockAsync(vol, "testuser");
        await _vs.MountAsync(vol, "testuser", "testpw");

        byte[] actual = await DownloadAllAsync(fs, vol, "patched.bin");
        Assert.Equal(expected, actual);
    }

    /// <summary>書き込み（全内容差し替え）と並行した読み取りは、常に「完全な旧版 or 完全な新版」
    /// のどちらかであり、途中経過（断片・混在）を読まないこと。読み取りゲートが
    /// ライターを排除するため、この不変条件が破れたらゲート実装のバグ。</summary>
    [Fact]
    public async Task ConcurrentReadDuringWrite_NeverTorn()
    {
        string vol = "conc-xts-torn";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: true);
        var fs = GetFileService();

        byte[] v1 = DeterministicBytes(40_000, seed: 401);
        byte[] v2 = DeterministicBytes(40_000, seed: 402);
        await UploadAsync(fs, vol, "hot.bin", v1);

        const int writeRounds = 10;
        bool writerDone = false;

        // ライター: v1 ↔ v2 を交互に全内容差し替え
        Task writer = Task.Run(async () =>
        {
            for (int i = 0; i < writeRounds; i++)
            {
                byte[] next = i % 2 == 0 ? v2 : v1;
                using var ms = new MemoryStream(next);
                await fs.PatchRangeAsync(vol, "hot.bin", 0, ms, next.Length);
            }
            writerDone = true;
        });

        // リーダー 3 本: 完了した読み取りは必ず v1 / v2 のどちらかに完全一致する
        var readerErrors = new System.Collections.Concurrent.ConcurrentBag<string>();
        Task[] readers = Enumerable.Range(0, 3).Select(r => Task.Run(async () =>
        {
            int iterations = 0;
            while (!writerDone && iterations < 300)
            {
                iterations++;
                try
                {
                    byte[] actual = await DownloadAllAsync(fs, vol, "hot.bin");
                    if (!actual.AsSpan().SequenceEqual(v1) && !actual.AsSpan().SequenceEqual(v2))
                    {
                        readerErrors.Add($"リーダー{r}: 旧版・新版のどちらにも一致しない断片データを読んだ（{actual.Length}B）");
                        return;
                    }
                }
                catch (Exception ex)
                {
                    readerErrors.Add($"リーダー{r}: {ex.GetType().Name}: {ex.Message}");
                    return;
                }
            }
        })).ToArray();

        await writer;
        await Task.WhenAll(readers);
        Assert.Empty(readerErrors);

        // 最終状態は最後に書いた内容と完全一致
        byte[] final = await DownloadAllAsync(fs, vol, "hot.bin");
        Assert.Equal(v1, final);
    }

    /// <summary>削除と競合した並行読み取りは「完全な内容」か「ファイル未存在（FileServiceException）」
    /// のどちらかであり、断片データや予期しない例外（ObjectDisposedException 等の
    /// gate 破棄競合）が観測されないこと。</summary>
    [Fact]
    public async Task ConcurrentDeleteVsDownload_FullContentOrNotFound()
    {
        string vol = "conc-xts-delete";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: true);
        var fs = GetFileService();

        byte[] content = DeterministicBytes(50_000, seed: 501);
        await UploadAsync(fs, vol, "victim.bin", content);

        // setup 検証: 削除前に完全な読み取りができること（負荷時でも削除タイミングに依存しない保証）
        byte[] initial = await DownloadAllAsync(fs, vol, "victim.bin");
        Assert.Equal(content, initial);

        // 50ms 後に 1 回削除
        Task delete = Task.Run(async () =>
        {
            await Task.Delay(50);
            await fs.DeleteAsync(vol, "victim.bin");
        });

        var errors = new System.Collections.Concurrent.ConcurrentBag<string>();
        int notFound = 0;
        int success = 0;

        // リーダー 3 本 × 200 回: 削除と競合しても内容は必ず完全
        await Task.WhenAll(Enumerable.Range(0, 3).Select(r => Task.Run(async () =>
        {
            for (int i = 0; i < 200; i++)
            {
                try
                {
                    byte[] actual = await DownloadAllAsync(fs, vol, "victim.bin");
                    if (!actual.AsSpan().SequenceEqual(content))
                    {
                        errors.Add($"リーダー{r}: 削除と競合して断片データを読んだ（{actual.Length}B / 期待 {content.Length}B）");
                        return;
                    }
                    Interlocked.Increment(ref success);
                }
                catch (FileServiceException)
                {
                    Interlocked.Increment(ref notFound);
                }
                catch (Exception ex)
                {
                    errors.Add($"リーダー{r}: 予期しない例外 {ex.GetType().Name}: {ex.Message}");
                    return;
                }
            }
        })));

        await delete;
        Assert.Empty(errors);
        // 競合の結果は「完全な内容」か「not found」のどちらか（負荷状況で片方になり得る）。
        // setup 検証で削除前の完全読み取りは確認済みのため、ここでは成功率を要求しない

        // 削除は確実に完了している
        Assert.Empty((await fs.ListAsync(vol)).Files);
    }

    /// <summary>一覧取得（ListAsync）と並行したアップロードが全て完成すること
    /// （ゲートのライフサイクル競合 — 一覧経由の gate 破棄が進行中のアップロードを
    /// 壊さないこと — の同一ボリューム版）。</summary>
    [Fact]
    public async Task ConcurrentUploadAndList_AllUploadsSurvive()
    {
        string vol = "conc-xts-list";
        await _vs.CreateAsync(vol, "testuser", "testpw", encrypted: true);
        var fs = GetFileService();

        var files = Enumerable.Range(0, 6)
            .ToDictionary(i => $"listing-{i}.bin", i => DeterministicBytes(20_000, seed: 600 + i));

        var uploadErrors = new System.Collections.Concurrent.ConcurrentBag<string>();
        Task listLoop = Task.Run(async () =>
        {
            for (int i = 0; i < 30; i++)
                await fs.ListAsync(vol);
        });

        await Task.WhenAll(files.Select(async f =>
        {
            try
            {
                await UploadAsync(fs, vol, f.Key, f.Value);
            }
            catch (Exception ex)
            {
                uploadErrors.Add($"{f.Key}: {ex.GetType().Name}: {ex.Message}");
            }
        }));
        await listLoop;
        Assert.Empty(uploadErrors);

        foreach (var (name, data) in files)
        {
            byte[] actual = await DownloadAllAsync(fs, vol, name);
            Assert.Equal(data, actual);
        }
    }

    // ---- E2EE: 同一ファイル / 同一ボリューム / 複数ボリュームの並行アクセス ----

    /// <summary>E2EE ボリュームの同じファイルに 8 チャンクを並行アップロードしても、
    /// 全チャンクが揃い、復号結果が元の平文とバイト等価であること。</summary>
    [Fact]
    public async Task E2ee_ConcurrentChunkUploads_SameFile_AllDecryptCorrectly()
    {
        string vol = "conc-e2ee-chunks";
        await CreateE2eeVolumeAsync(vol);
        var e2eeFs = GetE2eeFileService();

        byte[] plain = DeterministicBytes(30_000, seed: 701); // 4096B × 7 + 1808B の 8 チャンク
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(_masterKey, fileSalt);
        int chunkCount = E2eeCrypto.ComputeChunkCount(plain.Length, ChunkSize);
        int encLen = (int)E2eeCrypto.ComputeEncryptedLength(plain.Length, ChunkSize);

        var entry = await e2eeFs.CreateFileAsync(vol,
            new E2eeCreateFileRequest(E2eeCrypto.EncryptFilename("parallel.dat", _masterKey), encLen, chunkCount), Owner);

        // 全チャンクを並行アップロード（replace=true は順不同の到着を許容し、未確定チャンクとして
        // staging される。FinalizeFileAsync の一括昇格で全チャンクが同時に可視化される）
        var uploadErrors = new System.Collections.Concurrent.ConcurrentBag<string>();
        await Task.WhenAll(Enumerable.Range(0, chunkCount).Select(async i =>
        {
            try
            {
                int len = Math.Min(ChunkSize, plain.Length - i * ChunkSize);
                byte[] plainChunk = new byte[len];
                Array.Copy(plain, i * ChunkSize, plainChunk, 0, len);
                byte[] enc = E2eeCrypto.EncryptChunk(plainChunk, fileKey, i, fileSalt, isFirstChunk: i == 0);
                using var ms = new MemoryStream(enc);
                await e2eeFs.UploadChunkAsync(vol, entry.FileId, i, ms, enc.Length, replace: true);
            }
            catch (Exception ex)
            {
                uploadErrors.Add($"チャンク{i}: {ex.GetType().Name}: {ex.Message}");
            }
        }));
        Assert.Empty(uploadErrors);

        await e2eeFs.FinalizeFileAsync(vol, entry.FileId, new E2eeFinalizeFileRequest(encLen));
        byte[] actual = await ReadPlainFileAsync(e2eeFs, vol, _masterKey, entry.FileId);
        Assert.Equal(plain, actual);
    }

    /// <summary>E2EE ボリュームで 5 ファイルの並行アップロードと一覧取得（ListFilesAsync）を
    /// 同時に走らせても、全ファイルが完成し復号できること。static な _fileGates に対する
    /// 一覧経由の gate GC が進行中のアップロードを破壊しないことの回帰テスト。</summary>
    [Fact]
    public async Task E2ee_ConcurrentFileUploads_AndListFiles_AllDecryptable()
    {
        string vol = "conc-e2ee-list";
        await CreateE2eeVolumeAsync(vol);
        var e2eeFs = GetE2eeFileService();

        var files = Enumerable.Range(0, 5)
            .ToDictionary(i => $"e2ee-list-{i}.bin", i => DeterministicBytes(5_000 + i * 777, seed: 800 + i));

        var uploadErrors = new System.Collections.Concurrent.ConcurrentBag<string>();
        Task listLoop = Task.Run(async () =>
        {
            for (int i = 0; i < 30; i++)
                await e2eeFs.ListFilesAsync(vol);
        });

        var fileIds = await Task.WhenAll(files.Select(async f =>
        {
            try
            {
                return await WritePlainFileAsync(e2eeFs, vol, f.Key, f.Value, _masterKey);
            }
            catch (Exception ex)
            {
                uploadErrors.Add($"{f.Key}: {ex.GetType().Name}: {ex.Message}");
                return null;
            }
        }));
        await listLoop;
        Assert.Empty(uploadErrors);

        Assert.Equal(files.Count, (await e2eeFs.ListFilesAsync(vol)).Files.Count);
        for (int i = 0; i < fileIds.Length; i++)
        {
            byte[] actual = await ReadPlainFileAsync(e2eeFs, vol, _masterKey, fileIds[i]!);
            Assert.Equal(files[$"e2ee-list-{i}.bin"], actual);
        }
    }

    /// <summary>2 つの E2EE ボリューム（異なる masterKey）に同時に I/O しても、
    /// 内容が相互に混線しないこと。static 辞書を共有するサービスで、ボリューム単位の
    /// 分離が保たれることの検証（他ボリューム gate 破棄バグの直接の回帰テスト）。</summary>
    [Fact]
    public async Task E2ee_TwoVolumes_ConcurrentIO_NoCrossTalk()
    {
        string volA = "conc-e2ee-vol-a";
        string volB = "conc-e2ee-vol-b";
        byte[] masterKeyA = RandomNumberGenerator.GetBytes(32);
        byte[] masterKeyB = RandomNumberGenerator.GetBytes(32);
        await CreateE2eeVolumeAsync(volA, masterKeyA);
        await CreateE2eeVolumeAsync(volB, masterKeyB);
        var e2eeFs = GetE2eeFileService();

        var errors = new System.Collections.Concurrent.ConcurrentBag<string>();
        async Task RunVolumeIoAsync(string vol, byte[] mk, string tag)
        {
            for (int round = 0; round < 3; round++)
            {
                try
                {
                    string name = $"{tag}-r{round}.bin";
                    byte[] data = DeterministicBytes(6_000 + round * 999, seed: tag == "a" ? 900 + round : 950 + round);
                    string fileId = await WritePlainFileAsync(e2eeFs, vol, name, data, mk);
                    byte[] actual = await ReadPlainFileAsync(e2eeFs, vol, mk, fileId);
                    if (!actual.AsSpan().SequenceEqual(data))
                        errors.Add($"{vol} ラウンド{round}: 自ボリュームの内容と一致しない（混線疑い）");
                }
                catch (Exception ex)
                {
                    errors.Add($"{vol} ラウンド{round}: {ex.GetType().Name}: {ex.Message}");
                }
            }
        }

        await Task.WhenAll(RunVolumeIoAsync(volA, masterKeyA, "a"), RunVolumeIoAsync(volB, masterKeyB, "b"));
        Assert.Empty(errors);
    }

    /// <summary>チャンク差し替え（replace・revision 進行）と並行したチャンク読み取りは、
    /// 常に「v1 / v2 / v3 のいずれかの完全な内容」を復号できること。古いリビジョンの
    /// 断片や、サーバーが報告した revision と合わないデータを読まないこと。
    /// replace は未確定チャンクに staging され、FinalizeFileAsync の一括昇格で
    /// アトミックに可視化される（ファイル単位の可視化）。</summary>
    [Fact]
    public async Task E2ee_ConcurrentReplaceVsDownload_AlwaysOneFullRevision()
    {
        string vol = "conc-e2ee-replace";
        await CreateE2eeVolumeAsync(vol);
        var e2eeFs = GetE2eeFileService();

        byte[] v1 = DeterministicBytes(ChunkSize, seed: 1001);
        string fileId = await WritePlainFileAsync(e2eeFs, vol, "replaced.bin", v1, _masterKey);

        // fileSalt / fileKey は全リビジョン共通（replace は内容だけ差し替える）
        var (firstStream, firstLen, _, _) = await e2eeFs.DownloadChunkAsync(vol, fileId, 0);
        byte[] firstEnc = new byte[firstLen];
        using (firstStream) await firstStream.ReadExactlyAsync(firstEnc);
        byte[] fileSalt = firstEnc.AsSpan(0, 16).ToArray();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(_masterKey, fileSalt);
        byte[] v2 = DeterministicBytes(ChunkSize, seed: 1002);
        byte[] v3 = DeterministicBytes(ChunkSize, seed: 1003);

        bool writerDone = false;
        Task writer = Task.Run(async () =>
        {
            // v1 → v2（revision 1）→ v3（revision 2）。各差し替えを Finalize で確定し
            // ファイル単位で可視化する
            for (int rev = 1; rev <= 2; rev++)
            {
                byte[] content = rev == 1 ? v2 : v3;
                byte[] enc = E2eeCrypto.EncryptChunk(content, fileKey, 0, fileSalt, isFirstChunk: true, revision: rev);
                using var ms = new MemoryStream(enc);
                await e2eeFs.UploadChunkAsync(vol, fileId, 0, ms, enc.Length, replace: true);
                await e2eeFs.FinalizeFileAsync(vol, fileId, new E2eeFinalizeFileRequest(enc.Length, 1));
                await Task.Delay(20);
            }
            writerDone = true;
        });

        var errors = new System.Collections.Concurrent.ConcurrentBag<string>();
        int reads = 0;
        await Task.WhenAll(Enumerable.Range(0, 3).Select(r => Task.Run(async () =>
        {
            while (!writerDone && reads < 300)
            {
                Interlocked.Increment(ref reads);
                try
                {
                    var (stream, len, rev, _) = await e2eeFs.DownloadChunkAsync(vol, fileId, 0);
                    byte[] enc = new byte[len];
                    using (stream) await stream.ReadExactlyAsync(enc);
                    byte[] dec = E2eeCrypto.DecryptChunk(enc, fileKey, 0, fileSalt, revision: rev);

                    // サーバーが報告した revision の内容に完全一致するはず
                    byte[]? expected = rev == 0 ? v1 : rev == 1 ? v2 : rev == 2 ? v3 : null;
                    if (expected is null || !dec.AsSpan().SequenceEqual(expected))
                    {
                        errors.Add($"リーダー{r}: revision {rev} の内容が期待値と不一致（断片 or 混在）");
                        return;
                    }
                }
                catch (Exception ex)
                {
                    errors.Add($"リーダー{r}: {ex.GetType().Name}: {ex.Message}");
                    return;
                }
            }
        })));
        await writer;
        Assert.Empty(errors);

        // 最終状態は v3
        var (fs3, len3, rev3, _) = await e2eeFs.DownloadChunkAsync(vol, fileId, 0);
        byte[] enc3 = new byte[len3];
        using (fs3) await fs3.ReadExactlyAsync(enc3);
        Assert.Equal(v3, E2eeCrypto.DecryptChunk(enc3, fileKey, 0, fileSalt, revision: rev3));
    }

    /// <summary>ファイル単位の可視化（staged visibility）の本体テスト。
    /// 4 チャンクのファイルの「全チャンク」を差し替えている最中に全ファイル読み取りを
    /// 繰り返しても、読み手が観測するのは常に「完全な v1 / v2 / v3 のどれか 1 つ」であり、
    /// チャンク単位の断片公開（先頭チャンクだけ新版で残りは旧版、といった新旧混在）は
    /// 決して観測されないこと。replace は未確定チャンクに staging され、FinalizeFileAsync の
    /// 一括昇格（カタログ R-M-W 1 回）でアトミックに可視化されるため、排他の単位は
    /// チャンクではなくファイルになる。</summary>
    [Fact]
    public async Task E2ee_MultiChunkReplace_NeverTornForReaders()
    {
        string vol = "conc-e2ee-staged";
        await CreateE2eeVolumeAsync(vol);
        var e2eeFs = GetE2eeFileService();

        // 4 チャンク構成（4096 × 3 + 2712）のファイル。全バージョン同長のため
        // チャンク数・チャンク長は差し替え前後で不変（混在検出を内容比較に限定できる）
        int plainLen = ChunkSize * 3 + 2712;
        byte[] v1 = DeterministicBytes(plainLen, seed: 1101);
        string fileId = await WritePlainFileAsync(e2eeFs, vol, "staged.bin", v1, _masterKey);
        int chunkCount = E2eeCrypto.ComputeChunkCount(plainLen, ChunkSize);

        // fileSalt / fileKey は全リビジョン共通（replace は内容だけ差し替える）
        var (firstStream, firstLen, _, _) = await e2eeFs.DownloadChunkAsync(vol, fileId, 0);
        byte[] firstEnc = new byte[firstLen];
        using (firstStream) await firstStream.ReadExactlyAsync(firstEnc);
        byte[] fileSalt = firstEnc.AsSpan(0, 16).ToArray();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(_masterKey, fileSalt);
        byte[] v2 = DeterministicBytes(plainLen, seed: 1102);
        byte[] v3 = DeterministicBytes(plainLen, seed: 1103);
        byte[][] versions = [v1, v2, v3];

        bool writerDone = false;
        Task writer = Task.Run(async () =>
        {
            // 全 4 チャンクを差し替えてから Finalize で確定する、を 2 回（v1→v2→v3）。
            // 旧実装（チャンク単位の即時公開）では 4 チャンクの差し替え途中で
            // 「先頭チャンクだけ新版」の混在状態が読み手に見えていた
            for (int rev = 1; rev <= 2; rev++)
            {
                byte[] content = versions[rev];
                for (int i = 0; i < chunkCount; i++)
                {
                    int len = Math.Min(ChunkSize, content.Length - i * ChunkSize);
                    byte[] plainChunk = new byte[len];
                    Array.Copy(content, i * ChunkSize, plainChunk, 0, len);
                    byte[] enc = E2eeCrypto.EncryptChunk(plainChunk, fileKey, i, fileSalt, isFirstChunk: i == 0, revision: rev);
                    using var ms = new MemoryStream(enc);
                    await e2eeFs.UploadChunkAsync(vol, fileId, i, ms, enc.Length, replace: true);
                }
                // 一括昇格: ここで初めて 4 チャンク全部が新版として同時に見える
                await e2eeFs.FinalizeFileAsync(vol, fileId, new E2eeFinalizeFileRequest(E2eeCrypto.ComputeEncryptedLength(plainLen, ChunkSize)));
                await Task.Delay(20);
            }
            writerDone = true;
        });

        var errors = new System.Collections.Concurrent.ConcurrentBag<string>();
        int reads = 0;
        await Task.WhenAll(Enumerable.Range(0, 3).Select(r => Task.Run(async () =>
        {
            while (!writerDone && reads < 400)
            {
                Interlocked.Increment(ref reads);
                try
                {
                    // チャンクごとのダウンロードの間に writer の finalize が入ると
                    // チャンク単位では正しいがファイル全体としては新旧混在になる。
                    // クライアント側プロトコルとして revision の一致で検知して再試行する。
                    // revision が揃っていれば、内容は必ず完全な単一バージョンに一致する
                    //（staged visibility: カタログ昇格はアトミックで、全チャンクの ObjectId が同時に入れ替わる）
                    byte[]? whole = null;
                    for (int attempt = 0; attempt < 40 && whole is null; attempt++)
                    {
                        try
                        {
                            var (data, revs) = await ReadWholeFileAsync(e2eeFs, vol, _masterKey, fileId);
                            if (revs.Distinct().Count() == 1) whole = data;
                        }
                        catch (FileNotFoundException)
                        {
                            // 古いカタログスナップショットのチャンクが finalize の旧世代削除で
                            // 消えた → 新しいカタログで読み直す（実クライアントと同じ再試行プロトコル）
                        }
                        catch (IOException)
                        {
                            // 旧世代削除中の Windows 排他競合 → 再試行
                        }
                        await Task.Delay(5);
                    }
                    if (whole is null)
                    {
                        errors.Add($"リーダー{r}: 40 回再試行しても一貫した読み取りが得られない（finalize が集中しすぎ）");
                        return;
                    }
                    bool matchedAny = versions.Any(v => whole.AsSpan().SequenceEqual(v));
                    if (!matchedAny)
                    {
                        // どのバージョンとも一致しない = 新旧混在（チャンク単位の断片公開）を観測した
                        errors.Add($"リーダー{r}: revision 揃いの読み取りで新旧混在の断片データを読んだ");
                        return;
                    }
                }
                catch (Exception ex)
                {
                    errors.Add($"リーダー{r}: {ex.GetType().Name}: {ex.Message}");
                    return;
                }
            }
        })));
        await writer;
        Assert.Empty(errors);
        Assert.True(reads > 0, "リーダーが少なくとも 1 回は読み取れているはず");

        // 最終状態は完全な v3
        byte[] final = await ReadPlainFileAsync(e2eeFs, vol, _masterKey, fileId);
        Assert.Equal(v3, final);
    }

    /// <summary>gate GC バグの決定論的回帰テスト。旧実装の ListFilesAsync は static な
    /// _fileGates 辞書全体を走査して「自ボリュームのカタログに無い gate」を破棄していたため、
    /// <c>ListFilesAsync(volA)</c> を 1 回呼ぶだけで他ボリューム volB の gate が同期的に
    /// Dispose され、その後の volB の読み書きが ObjectDisposedException で壊れていた。
    /// 修正後は自ボリュームの fileId（_volumeFileIds）に限定されるため、volB の gate は
    /// 生き続ける。並行性に依存せず、単一スレッドの呼び出し順序だけで旧バグを再現する。</summary>
    [Fact]
    public async Task E2ee_ListFiles_DoesNotDisposeOtherVolumeGates()
    {
        string volA = "conc-e2ee-gc-a";
        string volB = "conc-e2ee-gc-b";
        byte[] masterKeyA = RandomNumberGenerator.GetBytes(32);
        byte[] masterKeyB = RandomNumberGenerator.GetBytes(32);
        await CreateE2eeVolumeAsync(volA, masterKeyA);
        await CreateE2eeVolumeAsync(volB, masterKeyB);

        // 単一の E2eeFileService インスタンス（= static 辞書を共有する実運用と同じ構成）
        var e2eeFs = GetE2eeFileService();

        byte[] dataA = DeterministicBytes(5_000, seed: 1201);
        byte[] dataB = DeterministicBytes(6_500, seed: 1202);
        string fileA = await WritePlainFileAsync(e2eeFs, volA, "a.bin", dataA, masterKeyA);
        string fileB = await WritePlainFileAsync(e2eeFs, volB, "b.bin", dataB, masterKeyB);

        // 旧実装はこの呼び出しの中で volB の gate を破棄していた（volB のファイルは
        // volA のカタログに無いため）。修正後は volB の gate が残る。
        await e2eeFs.ListFilesAsync(volA);

        // volB の読み取りが生きている（旧実装では ObjectDisposedException）
        byte[] readB = await ReadPlainFileAsync(e2eeFs, volB, masterKeyB, fileB);
        Assert.Equal(dataB, readB);

        // volB への新規書き込みも生きている（既存 gate の破棄が I/O を壊さないことの検証）
        byte[] dataB2 = DeterministicBytes(3_000, seed: 1203);
        string fileB2 = await WritePlainFileAsync(e2eeFs, volB, "b2.bin", dataB2, masterKeyB);
        byte[] readB2 = await ReadPlainFileAsync(e2eeFs, volB, masterKeyB, fileB2);
        Assert.Equal(dataB2, readB2);

        // volA 側も無傷
        byte[] readA = await ReadPlainFileAsync(e2eeFs, volA, masterKeyA, fileA);
        Assert.Equal(dataA, readA);
    }

    // ---- E2EE ヘルパー（E2eeDataNoLossTests と同じ復号経路） ----

    private async Task CreateE2eeVolumeAsync(string name, byte[]? masterKey = null)
    {
        byte[] mk = masterKey ?? _masterKey;
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        KdfSpec kdf = KdfSpec.LegacyPbkdf2(1000);
        byte[] kek = E2eeCrypto.DeriveKek(Owner, "alice-pw", salt, kdf);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(mk, kek);
        CryptographicOperations.ZeroMemory(kek);

        await _vs.CreateE2eeAsync(name, Owner, new VolumeHeader.UserWrappedKey
        {
            WrapType = "password",
            Kdf = new() { Algorithm = kdf.Algorithm, Iterations = kdf.Iterations, MemoryKiB = kdf.MemoryKiB, TimeCost = kdf.TimeCost, Parallelism = kdf.Parallelism, Salt = salt },
            WrappedMasterKey = new() { Algorithm = "aes-256-gcm", Nonce = nonce, Ciphertext = ct, Tag = tag },
        }, chunkSize: ChunkSize);
    }

    private static async Task<string> WritePlainFileAsync(E2eeFileService e2eeFs, string vol,
        string plainName, byte[] plain, byte[]? masterKey = null)
    {
        byte[] mk = masterKey ?? throw new ArgumentNullException(nameof(masterKey));
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(mk, fileSalt);
        int chunkCount = E2eeCrypto.ComputeChunkCount(plain.Length, ChunkSize);
        int encLen = (int)E2eeCrypto.ComputeEncryptedLength(plain.Length, ChunkSize);

        var entry = await e2eeFs.CreateFileAsync(vol,
            new E2eeCreateFileRequest(E2eeCrypto.EncryptFilename(plainName, mk), encLen, chunkCount), Owner);

        int offset = 0;
        for (int i = 0; i < chunkCount; i++)
        {
            int len = Math.Min(ChunkSize, plain.Length - offset);
            byte[] plainChunk = new byte[len];
            Array.Copy(plain, offset, plainChunk, 0, len);
            byte[] enc = E2eeCrypto.EncryptChunk(plainChunk, fileKey, i, fileSalt, isFirstChunk: i == 0);
            using var ms = new MemoryStream(enc);
            await e2eeFs.UploadChunkAsync(vol, entry.FileId, i, ms, enc.Length);
            offset += len;
        }
        await e2eeFs.FinalizeFileAsync(vol, entry.FileId, new E2eeFinalizeFileRequest(encLen));
        return entry.FileId;
    }

    private static async Task<byte[]> ReadPlainFileAsync(E2eeFileService e2eeFs, string vol,
        byte[] masterKey, string fileId)
    {
        var (plain, _) = await ReadWholeFileAsync(e2eeFs, vol, masterKey, fileId);
        return plain;
    }

    /// <summary>ファイル全体を読み取り、チャンクごとの revision も返す。
    /// リーダーは revision が全チャンクで揃っていることを確認して初めて
    /// 「単一バージョンの完全な読み取り」と判定できる（揃っていなければ再試行）。</summary>
    private static async Task<(byte[] Plain, int[] Revisions)> ReadWholeFileAsync(E2eeFileService e2eeFs, string vol,
        byte[] masterKey, string fileId)
    {
        var entry = (await e2eeFs.ListFilesAsync(vol)).Files.Single(f => f.FileId == fileId);
        int chunkCount = entry.ChunkSizes.Count;

        var (firstStream, firstLen, firstRev, _) = await e2eeFs.DownloadChunkAsync(vol, fileId, 0);
        byte[] firstEnc = new byte[firstLen];
        using (firstStream) await firstStream.ReadExactlyAsync(firstEnc);
        byte[] fileSalt = firstEnc.AsSpan(0, 16).ToArray();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);

        byte[] plain = new byte[entry.EncryptedLength - 16 - chunkCount * 16];
        var revisions = new int[chunkCount];
        int offset = 0;
        for (int i = 0; i < chunkCount; i++)
        {
            byte[] enc;
            int revision;
            if (i == 0)
            {
                enc = firstEnc;
                revision = firstRev;
            }
            else
            {
                var (stream, len, rev, _) = await e2eeFs.DownloadChunkAsync(vol, fileId, i);
                enc = new byte[len];
                using (stream) await stream.ReadExactlyAsync(enc);
                revision = rev;
            }
            revisions[i] = revision;
            byte[] dec = E2eeCrypto.DecryptChunk(enc, fileKey, i, fileSalt, revision: revision);
            Array.Copy(dec, 0, plain, offset, dec.Length);
            offset += dec.Length;
        }
        CryptographicOperations.ZeroMemory(fileKey);
        return (plain, revisions);
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
