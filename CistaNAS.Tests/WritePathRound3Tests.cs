using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using CistaNAS.Client;
using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;
using DokanNet;

namespace CistaNAS.Tests;

/// <summary>
/// 再レビュー round 3 指摘の回帰テスト。
/// V3 で導入した「persist をバッファゲート外で行う」設計が露出させた欠陥:
/// - 新規 E2EE ファイル初回 persist 後の同一ハンドル再 persist が再度新規作成しデータ破壊
/// - 新規作成失敗・切り詰め領域チャンクのロールバック欠落
/// - Cleanup が進行中の persist を待たずにバッファを破棄
/// - 非E2EE の純粋な SetEndOfFile 拡張が消える / 切り詰め PUT がダウンロード失敗を握りつぶす
/// - 切り詰め→拡張で旧内容が復活する（plain / E2EE RMW）
/// - グローバル persist ゲートが無関係ファイルの persist を塞ぐ
/// </summary>
public class WritePathRound3Tests
{
    private const int ChunkSize = 4096;
    private const string Volume = "vol";

    private static byte[] Pattern(int len, int seed = 0)
        => Enumerable.Range(0, len).Select(i => (byte)((i + seed) % 251)).ToArray();

    /// <summary>Dokan コールバックを実ドライバなしで呼ぶためのスタブ。</summary>
    private sealed class StubFileInfo(object? context = null) : IDokanFileInfo
    {
        public object? Context { get; set; } = context;
        public bool DeletePending { get; set; }
        public bool IsDirectory { get; set; }
        public bool NoCache { get; set; }
        public bool PagingIo { get; set; }
        public int ProcessId => 1;
        public bool SynchronousIo { get; set; }
        public bool WriteToEndOfFile { get; set; }
        public System.Security.Principal.WindowsIdentity GetRequestor() => throw new NotSupportedException();
        public bool TryResetTimeout(int milliseconds) => true;
    }

    /// <summary>
    /// 既存 E2EE ファイル 1 つ + 新規作成（create-file）を模倣する Fake。
    /// create-file の回数を記録し、upload-chunk / create-file の失敗注入・ブロックが可能。
    /// </summary>
    private sealed class FakeE2eeServer(byte[] masterKey, byte[] plain, byte[] fileKey, byte[] fileSalt) : HttpMessageHandler
    {
        public const string FileId = "f1";

        public Dictionary<int, (byte[] Cipher, int Revision)> Chunks { get; } = new();
        public List<(long EncryptedLength, int? ChunkCount)> FinalizeRequests { get; } = new();
        public int ChunkCount { get; private set; }
        public int CreateFileCount { get; private set; }
        public int FailNextUploads { get; set; }
        public int FailNextCreateFiles { get; set; }

        private readonly TaskCompletionSource _uploadReached = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task UploadReached => _uploadReached.Task;
        public TaskCompletionSource? UploadRelease { get; set; }

        public FakeE2eeServer Init()
        {
            int count = (plain.Length + ChunkSize - 1) / ChunkSize;
            for (int i = 0; i < count; i++)
            {
                int len = Math.Min(ChunkSize, plain.Length - i * ChunkSize);
                byte[] enc = E2eeCrypto.EncryptChunk(
                    plain[(i * ChunkSize)..(i * ChunkSize + len)], fileKey, i, fileSalt, isFirstChunk: i == 0);
                Chunks[i] = (enc, 0);
            }
            ChunkCount = count;
            return this;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string path = request.RequestUri!.AbsolutePath;
            var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            string op = segments.Length >= 5 ? segments[4] : "";

            if (op == "create-file" && request.Method == HttpMethod.Post)
            {
                if (FailNextCreateFiles > 0)
                {
                    FailNextCreateFiles--;
                    return JsonR(HttpStatusCode.InternalServerError, "テスト用の作成失敗");
                }
                CreateFileCount++;
                return JsonR(HttpStatusCode.OK,
                    $$"""{"fileId":"new-{{CreateFileCount}}","writeLeaseToken":"new-lease-{{CreateFileCount}}"}""");
            }

            if (op == "files" && request.Method == HttpMethod.Get && segments.Length == 5)
            {
                long encLength = E2eeCrypto.SaltSize + plain.Length + (long)E2eeCrypto.GcmTagSize * Chunks.Count;
                var payload = new
                {
                    files = new[]
                    {
                        new
                        {
                            fileId = FileId,
                            encryptedName = E2eeCrypto.EncryptFilename("plain.txt", masterKey),
                            encryptedLength = encLength,
                            chunkCount = ChunkCount,
                            createdAt = "2026-01-01T00:00:00Z",
                            modifiedAt = "2026-01-01T00:00:00Z",
                        },
                    },
                };
                return JsonR(HttpStatusCode.OK, System.Text.Json.JsonSerializer.Serialize(payload));
            }

            // .../files/{id}/write-lease/renew
            if (op == "files" && segments.Length >= 7 && segments[6] == "write-lease"
                && segments[^1] == "renew" && request.Method == HttpMethod.Post)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));

            // .../files/{id}/write-lease
            if (op == "files" && segments.Length >= 6 && segments[^1] == "write-lease")
            {
                if (request.Method == HttpMethod.Post)
                    return JsonR(HttpStatusCode.OK, """{"token":"lease-1"}""");
                if (request.Method == HttpMethod.Delete)
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
            }

            if (op == "chunk-hash" && request.Method == HttpMethod.Get)
            {
                int index = int.Parse(segments[6]);
                if (index >= ChunkCount || !Chunks.ContainsKey(index))
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
                return JsonR(HttpStatusCode.OK,
                    $$"""{"hash":"fake-hash","revision":{{Chunks[index].Revision}}}""");
            }

            if (op == "download-chunk" && request.Method == HttpMethod.Get)
            {
                int index = int.Parse(segments[6]);
                if (index >= ChunkCount || !Chunks.ContainsKey(index))
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
                byte[] enc = Chunks[index].Cipher;
                var res = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(enc) };
                res.Headers.Add("X-Chunk-Revision", Chunks[index].Revision.ToString());
                return Task.FromResult(res);
            }

            if (op == "upload-chunk" && request.Method == HttpMethod.Post)
            {
                int index = int.Parse(segments[6]);
                if (index > ChunkCount)
                    return JsonR(HttpStatusCode.BadRequest, "範囲外");
                _uploadReached.TrySetResult();
                if (FailNextUploads > 0)
                {
                    FailNextUploads--;
                    return JsonR(HttpStatusCode.InternalServerError, "テスト用のアップロード失敗");
                }
                UploadRelease?.Task.Wait();
                byte[] cipher = request.Content!.ReadAsByteArrayAsync(ct).GetAwaiter().GetResult();
                bool isReplace = index < ChunkCount && Chunks.ContainsKey(index);
                int revision = isReplace ? Chunks[index].Revision + 1 : 0;
                Chunks[index] = (cipher, revision);
                if (index >= ChunkCount) ChunkCount = index + 1;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
            }

            if (op == "finalize-file" && request.Method == HttpMethod.Patch)
            {
                string body = request.Content!.ReadAsStringAsync(ct).GetAwaiter().GetResult();
                using var doc = System.Text.Json.JsonDocument.Parse(body);
                long encLen = doc.RootElement.GetProperty("actualEncryptedLength").GetInt64();
                int? chunkCount = doc.RootElement.TryGetProperty("chunkCount", out var cc)
                    && cc.ValueKind == System.Text.Json.JsonValueKind.Number ? cc.GetInt32() : null;
                FinalizeRequests.Add((encLen, chunkCount));
                if (chunkCount is int n && n < ChunkCount)
                {
                    for (int i = n; i < ChunkCount; i++) Chunks.Remove(i);
                    ChunkCount = n;
                }
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static Task<HttpResponseMessage> JsonR(HttpStatusCode code, string json) =>
            Task.FromResult(new HttpResponseMessage(code)
            {
                Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json"),
            });
    }

    /// <summary>非E2EE 複数ファイルの内容を保持する Fake。PUT / PATCH のブロックと GET 失敗の注入が可能。</summary>
    private sealed class PlainServer : HttpMessageHandler
    {
        public Dictionary<string, byte[]> Files { get; } = new();
        public int PutCount { get; private set; }
        public int PatchCount { get; private set; }
        public int FailNextGets { get; set; }

        /// <summary>このリストにあるファイルへの PUT/PATCH を BlockRelease までブロックする。</summary>
        public HashSet<string> BlockNames { get; } = new();

        private readonly TaskCompletionSource _blockReached = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task BlockReached => _blockReached.Task;
        public TaskCompletionSource? BlockRelease { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var segments = request.RequestUri!.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            // /api/v1/files/{vol}/{name}
            string name = segments[^1];

            if (request.Method == HttpMethod.Post)
            {
                if (BlockNames.Contains(name))
                {
                    _blockReached.TrySetResult();
                    BlockRelease?.Task.Wait();
                }
                Files[name] = request.Content!.ReadAsByteArrayAsync(ct).GetAwaiter().GetResult();
                PutCount++;
                return Meta(name);
            }

            if (request.Method == HttpMethod.Patch)
            {
                if (BlockNames.Contains(name))
                {
                    _blockReached.TrySetResult();
                    BlockRelease?.Task.Wait();
                }
                long offset = long.Parse(request.RequestUri.Query.Replace("?offset=", ""));
                byte[] data = request.Content!.ReadAsByteArrayAsync(ct).GetAwaiter().GetResult();
                byte[] content = Files.TryGetValue(name, out var existing) ? existing : Array.Empty<byte>();
                int newLength = (int)Math.Max(content.Length, offset + data.Length);
                byte[] updated = new byte[newLength];
                content.CopyTo(updated, 0);
                data.CopyTo(updated, (int)offset);
                Files[name] = updated;
                PatchCount++;
                return Meta(name);
            }

            if (request.Method == HttpMethod.Get)
            {
                if (FailNextGets > 0)
                {
                    FailNextGets--;
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError));
                }
                byte[] content = Files.TryGetValue(name, out var existing) ? existing : Array.Empty<byte>();
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(content) });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private Task<HttpResponseMessage> Meta(string name)
        {
            byte[] content = Files.TryGetValue(name, out var existing) ? existing : Array.Empty<byte>();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    $$"""{"name":"{{name}}","length":{{content.Length}},"createdAt":"2026-01-01T00:00:00Z","modifiedAt":"2026-01-01T00:00:00Z"}""",
                    System.Text.Encoding.UTF8, "application/json"),
            });
        }
    }

    private static (CistaNasFileSystem Fs, FakeE2eeServer Server, byte[] FileSalt, byte[] FileKey, byte[] Plain)
        CreateExistingE2eeFile(int plainLength)
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] plain = Pattern(plainLength);
        byte[] fileSalt = RandomNumberGenerator.GetBytes(16);
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        var server = new FakeE2eeServer(masterKey, plain, fileKey, fileSalt).Init();
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, masterKey, Volume, chunkSize: ChunkSize);
        return (fs, server, fileSalt, fileKey, plain);
    }

    // ---- F1: 新規 E2EE ファイルの初回 persist 後の再 persist ----

    [Fact]
    public void 新規E2EEファイルの初回保存後に同一ハンドルで再保存すると新規作成せず差分保存される()
    {
        // 回帰: 初回 persist 成功時に CompleteChunkUpload がダーティチャンクを解放し
        // _existingChunkCount を進めるのに ExistingFileId が null のままのため、
        // 次の persist が再び新規ファイルを作り、解放済みチャンクを再取得できず
        // 承認済みデータが破壊されていた。
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] fileSalt = RandomNumberGenerator.GetBytes(16);
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        var server = new FakeE2eeServer(masterKey, Array.Empty<byte>(), fileKey, fileSalt);
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, masterKey, Volume, chunkSize: ChunkSize);

        byte[] first = Pattern(5000, seed: 10); // チャンク 0-1
        var ws = new CistaNasFileSystem.E2eeChunkWriteState(fs, "new.txt", null);
        var info = new StubFileInfo { Context = ws };

        ws.Write(first, 0, first.Length, 0);
        fs.UploadWriteState(ws);
        Assert.Equal(1, server.CreateFileCount); // 初回は新規作成

        // 実装側が生成した fileSalt は暗号文先頭に埋め込まれるため、そこから鍵を導出する
        byte[] salt0 = new byte[E2eeCrypto.SaltSize];
        Buffer.BlockCopy(server.Chunks[0].Cipher, 0, salt0, 0, E2eeCrypto.SaltSize);
        byte[] newFileKey = E2eeCrypto.DeriveFileKey(masterKey, salt0);

        // 同一ハンドルでの追記書き込み → 2 回目の persist は差分保存であるべき
        byte[] patch = Pattern(100, seed: 90);
        ws.Write(patch, 0, patch.Length, 100);
        fs.UploadWriteState(ws);

        // 回帰: 2 回目で新規ファイルをもう一つ作ってしまう
        Assert.Equal(1, server.CreateFileCount);

        // 内容: チャンク 0 は初回内容 + patch、チャンク 1 は初回内容のまま
        byte[] chunk0 = E2eeCrypto.DecryptChunk(server.Chunks[0].Cipher, newFileKey, 0, salt0, revision: 1);
        byte[] expected0 = first[..ChunkSize];
        patch.CopyTo(expected0, 100);
        Assert.Equal(expected0, chunk0);
        byte[] chunk1 = E2eeCrypto.DecryptChunk(server.Chunks[1].Cipher, newFileKey, 1, salt0, revision: 0);
        Assert.Equal(first[ChunkSize..], chunk1);
    }

    // ---- F5: 新規 E2EE ファイルの create-file 失敗時のロールバック ----

    [Fact]
    public void 新規E2EEファイルの作成失敗時にバッファは未永続化として保持される()
    {
        // 回帰: スナップショット（pending 取り込み）が CreateFileAsync より前に行われるのに、
        // ロールバックはその後の try にしか配線されていなかった。作成に失敗すると
        // pending = 0 のまま例外が流れ、Cleanup の再試行経路も死ぬ。
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] fileSalt = RandomNumberGenerator.GetBytes(16);
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        var server = new FakeE2eeServer(masterKey, Array.Empty<byte>(), fileKey, fileSalt)
        {
            FailNextCreateFiles = 1,
        };
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, masterKey, Volume, chunkSize: ChunkSize);

        byte[] data = Pattern(100, seed: 30);
        var ws = new CistaNasFileSystem.E2eeChunkWriteState(fs, "new.txt", null);
        ws.Write(data, 0, data.Length, 0);

        Assert.ThrowsAny<Exception>(() => fs.UploadWriteState(ws));
        // 回帰: ロールバックされず pending が消えている
        Assert.True(ws.HasPending, "作成失敗後にバッファが未永続化として保持されていません");

        // 復旧後の再 persist で完成する
        fs.UploadWriteState(ws);
        Assert.Equal(1, server.CreateFileCount);
        // 実装側が生成した fileSalt は暗号文先頭に埋め込まれるため、そこから鍵を導出する
        byte[] salt0 = new byte[E2eeCrypto.SaltSize];
        Buffer.BlockCopy(server.Chunks[0].Cipher, 0, salt0, 0, E2eeCrypto.SaltSize);
        byte[] newFileKey = E2eeCrypto.DeriveFileKey(masterKey, salt0);
        byte[] chunk0 = E2eeCrypto.DecryptChunk(server.Chunks[0].Cipher, newFileKey, 0, salt0, revision: 0);
        Assert.Equal(data, chunk0);
    }

    // ---- F3: 切り詰め領域チャンクのロールバック ----

    [Fact]
    public void E2EE切り詰めを含む保存の失敗後も切り詰め領域の書き込みが保持される()
    {
        // 回帰: TakeDirtyChunksForUpload が切り詰め領域（ci >= chunkCount）のチャンクを
        // アップロード成功前にゼロ化・除去し、スナップショット外のためロールバックできなかった。
        var (fs, server, fileSalt, fileKey, plain) = CreateExistingE2eeFile(10000); // 3 チャンク
        byte[] data0 = Pattern(100, seed: 40);
        byte[] data2 = Pattern(100, seed: 41);

        var ws = new CistaNasFileSystem.E2eeChunkWriteState(fs, "plain.txt", FakeE2eeServer.FileId);
        ws.Write(data0, 0, data0.Length, 0);
        ws.Write(data2, 0, data2.Length, 9000);

        // 切り詰め（1000B = 1 チャンク）を含む persist を失敗させる
        ws.SetDeclaredSize(1000);
        server.FailNextUploads = 1;
        Assert.ThrowsAny<Exception>(() => fs.UploadWriteState(ws));

        // 切り詰めを取り消して再 persist: 切り詰め領域の書き込み（9000..9100）が生きていなければならない
        ws.SetDeclaredSize(10000);
        fs.UploadWriteState(ws);

        Assert.Equal(1, server.Chunks[2].Revision); // 再アップロードされている
        byte[] chunk2 = E2eeCrypto.DecryptChunk(server.Chunks[2].Cipher, fileKey, 2, fileSalt, revision: 1);
        byte[] expected2 = plain[8192..]; // 旧サーバー内容
        data2.CopyTo(expected2, 9000 - 8192);
        Assert.Equal(expected2, chunk2);
    }

    // ---- F4: Cleanup が進行中の persist を待たない ----

    [Fact]
    public void Cleanupは進行中のアップロード完了を待ってからバッファを破棄する()
    {
        // 回帰: UploadWriteState の HasPending チェックが persist ゲートの外にあり、
        // 別スレッドの persist がスナップショット済み（HasPending == false）で通信中の間に
        // Cleanup が早期 return して Dispose（リース解放・バッファゼロ化）できていた。
        var (fs, server, fileSalt, fileKey, plain) = CreateExistingE2eeFile(5000);
        byte[] data = Pattern(100, seed: 50);

        var ws = new CistaNasFileSystem.E2eeChunkWriteState(fs, "plain.txt", FakeE2eeServer.FileId);
        var info = new StubFileInfo { Context = ws };
        ws.Write(data, 0, data.Length, 0);

        server.UploadRelease = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<NtStatus> flush = Task.Run(() => fs.FlushFileBuffers("\\" + "plain.txt", info));
        Assert.True(server.UploadReached.Wait(TimeSpan.FromSeconds(10)), "upload-chunk に到達しませんでした");

        // アップロード中に Cleanup を呼ぶ（正しくは persist の完了を待ってブロックする）
        Task cleanup = Task.Run(() => fs.Cleanup("\\" + "plain.txt", info));
        Assert.False(cleanup.Wait(300), "Cleanup が進行中のアップロードを待たずに完了しました");
        Assert.True(ReferenceEquals(info.Context, ws), "Cleanup がアップロード中にバッファを破棄しました");

        server.UploadRelease.TrySetResult();
        Assert.True(flush.Wait(TimeSpan.FromSeconds(10)));
        Assert.Equal(DokanResult.Success, flush.Result);
        Assert.True(cleanup.Wait(TimeSpan.FromSeconds(10)));
        Assert.Null(info.Context);

        byte[] chunk0 = E2eeCrypto.DecryptChunk(server.Chunks[0].Cipher, fileKey, 0, fileSalt, revision: 1);
        byte[] expected = plain[..ChunkSize];
        data.CopyTo(expected, 0);
        Assert.Equal(expected, chunk0);
    }

    // ---- F7 (E2EE RMW): 切り詰め後の拡張領域 ----

    [Fact]
    public void E2EE切り詰め後の拡張領域はRMWで旧内容を復活させない()
    {
        // 回帰: SetEndOfFile で切り詰めた後に拡張領域へ書き込むと、RMW が既存チャンクを
        // そのまま取り込むため、切り詰め点〜書き込み位置の隙間に旧サーバー内容が復活していた。
        // truncate-then-extend のセマンティクスでは隙間はゼロでなければならない。
        var (fs, server, fileSalt, fileKey, plain) = CreateExistingE2eeFile(10000);
        byte[] data = Pattern(100, seed: 60);

        var ws = new CistaNasFileSystem.E2eeChunkWriteState(fs, "plain.txt", FakeE2eeServer.FileId);
        var info = new StubFileInfo { Context = ws };

        Assert.Equal(DokanResult.Success, fs.SetEndOfFile("\\" + "plain.txt", 5000, info));
        Assert.Equal(DokanResult.Success, fs.WriteFile("\\" + "plain.txt", data, out _, 6000, info));
        Assert.Equal(DokanResult.Success, fs.FlushFileBuffers("\\" + "plain.txt", info));

        // チャンク 1: [4096,5000) 旧内容 + [5000,6000) ゼロ + [6000,6100) 書き込み
        byte[] chunk1 = E2eeCrypto.DecryptChunk(server.Chunks[1].Cipher, fileKey, 1, fileSalt, revision: 1);
        byte[] expected = new byte[6100 - 4096];
        plain.AsSpan(4096, 904).CopyTo(expected);
        data.CopyTo(expected, 6000 - 4096);
        Assert.Equal(expected, chunk1);
    }

    // ---- F2: 非E2EE の純粋な SetEndOfFile 拡張 ----

    [Fact]
    public void 非E2EE_SetEndOfFileによる純粋な拡張が全体PUTで永続化される()
    {
        // 回帰: 書き込みなしの純粋な拡張で taken.Count == 0 になり、早期 return が
        // TakeRangesForUpload が消費した pending を戻さないため拡張が永続化されなかった。
        var server = new PlainServer();
        server.Files["a.txt"] = Pattern(100, seed: 70);
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, Volume);

        var ws = new CistaNasFileSystem.PlainRangeWriteState(fs, "a.txt", "a.txt", existingLength: 100);
        ws.SetDeclaredSize(500);

        fs.UploadWriteState(ws);

        Assert.Equal(1, server.PutCount);
        byte[] content = server.Files["a.txt"];
        Assert.Equal(500, content.Length);
        byte[] expected = new byte[500];
        Pattern(100, seed: 70).CopyTo(expected, 0);
        Assert.Equal(expected, content); // 拡張領域はゼロ
    }

    // ---- F6: 切り詰め PUT のダウンロード失敗 ----

    [Fact]
    public void 非E2EE_切り詰め時にダウンロード失敗を握りつぶさず保存を失敗させる()
    {
        // 回帰: 切り詰め PUT が DownloadFileAsync の失敗を握りつぶし、全ゼロバッファを
        // PUT して既存内容を破壊していた。失敗時は persist を失敗させロールバックする。
        var server = new PlainServer();
        server.Files["a.txt"] = Pattern(10000, seed: 80);
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, Volume);

        byte[] data = Pattern(100, seed: 81);
        var ws = new CistaNasFileSystem.PlainRangeWriteState(fs, "a.txt", "a.txt", existingLength: 10000);
        ws.Write(data, 0, data.Length, 0);
        ws.SetDeclaredSize(5000);

        server.FailNextGets = 1;
        Assert.ThrowsAny<Exception>(() => fs.UploadWriteState(ws));
        // サーバー内容は破壊されていない
        Assert.Equal(10000, server.Files["a.txt"].Length);

        // 復旧後の再 persist で正しい内容が確定する
        fs.UploadWriteState(ws);
        byte[] expected = server.Files["a.txt"][..5000];
        data.CopyTo(expected, 0);
        Assert.Equal(expected, server.Files["a.txt"]);
    }

    // ---- F7 (plain): 切り詰め後拡張の隙間 ----

    [Fact]
    public void 非E2EE_切り詰め後拡張の隙間はゼロで埋められる()
    {
        // 回帰: 切り詰め PUT が旧サーバー内容を [0, snapshotSize) 全体にコピーするため、
        // 縮小→拡張の順序で切り詰め点〜書き込み位置の隙間に旧内容が復活していた。
        var server = new PlainServer();
        server.Files["a.txt"] = Pattern(10000, seed: 90);
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, Volume);

        byte[] data = Pattern(100, seed: 91);
        var ws = new CistaNasFileSystem.PlainRangeWriteState(fs, "a.txt", "a.txt", existingLength: 10000);
        ws.SetDeclaredSize(5000);   // 10000 → 5000 に切り詰め
        ws.Write(data, 0, data.Length, 6000); // 切り詰め点を越えて拡張（CurrentSize = 6100）

        fs.UploadWriteState(ws);

        byte[] content = server.Files["a.txt"];
        Assert.Equal(6100, content.Length);
        // 隙間 [5000, 6000) はゼロ（回帰: 旧ファイルのバイトが復活する）
        Assert.True(content[5000..6000].All(b => b == 0), "切り詰め後の拡張隙間に旧内容が復活しています");
        byte[] expectedTail = new byte[100];
        data.CopyTo(expectedTail, 0);
        Assert.Equal(expectedTail, content[6000..6100]);
    }

    // ---- Round 4 回帰: 新規 E2EE ファイルの切り詰めを含む保存 ----

    [Fact]
    public void 新規E2EEファイルの切り詰め領域を含む保存が失敗しない()
    {
        // 回帰 (round 4): TakeDirtyChunksForUpload が切り詰め領域 (ci >= chunkCount) を
        // スナップショットに含めるようになったことで、新規ファイル経路のアップロードループで
        // chunkLen = min(chunkSize, plainLength - ci*chunkSize) が負になり
        // ResizeChunk が例外を投げ、persist が必ず失敗していた。
        // （既存ファイル経路には ci >= chunkCount スキップがあるが新規経路になかった）
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] fileSalt = RandomNumberGenerator.GetBytes(16);
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        var server = new FakeE2eeServer(masterKey, Array.Empty<byte>(), fileKey, fileSalt);
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, masterKey, Volume, chunkSize: ChunkSize);

        byte[] data = Pattern(100, seed: 120);
        var ws = new CistaNasFileSystem.E2eeChunkWriteState(fs, "new.txt", null);
        ws.Write(data, 0, data.Length, 9000); // チャンク 2 に書き込み（チャンク 0-1 は隙間）
        ws.SetDeclaredSize(1000);             // 切り詰め → チャンク 2 は切り詰め領域になる

        // 回帰: chunkLen が負になり例外で persist 全体が失敗する
        fs.UploadWriteState(ws);

        // 切り詰め後の 1 チャンク（1000B）だけが確定する
        Assert.Equal(
            (E2eeCrypto.ComputeEncryptedLength(1000, ChunkSize), 1),
            server.FinalizeRequests[^1]);
        Assert.Equal(1, server.ChunkCount);
        byte[] salt0 = new byte[E2eeCrypto.SaltSize];
        Buffer.BlockCopy(server.Chunks[0].Cipher, 0, salt0, 0, E2eeCrypto.SaltSize);
        byte[] newFileKey = E2eeCrypto.DeriveFileKey(masterKey, salt0);
        // 切り詰め後はチャンク 0 のみが残る。書き込み (offset 9000) は切り詰め領域に消え、
        // チャンク 0 は未書き込みの隙間なので RMW ゼロ埋めであるべき（旧内容の復活なし）
        byte[] expected = new byte[1000];
        Assert.Equal(expected, E2eeCrypto.DecryptChunk(server.Chunks[0].Cipher, newFileKey, 0, salt0, revision: 0));
    }

    // ---- Round 4 回帰: FlushFileBuffers が進行中 persist の成否を待たない ----

    [Fact]
    public void FlushFileBuffersは進行中の保存の完了を待ってから結果を返す()
    {
        // 回帰 (round 4): HasPending == false の間（進行中 persist がスナップショット済み）の
        // FlushFileBuffers が即座に Success を返すため、その persist が失敗しても
        // Windows には「永続化成功」と報告されたままになる。
        var (fs, server, fileSalt, fileKey, plain) = CreateExistingE2eeFile(5000);
        byte[] data = Pattern(100, seed: 130);

        var ws = new CistaNasFileSystem.E2eeChunkWriteState(fs, "plain.txt", FakeE2eeServer.FileId);
        var info = new StubFileInfo { Context = ws };
        ws.Write(data, 0, data.Length, 0);

        // 1 回目の flush が進行中の間に 2 回目の flush を呼ぶ
        server.FailNextUploads = 1;
        server.UploadRelease = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<NtStatus> flush1 = Task.Run(() => fs.FlushFileBuffers("\\" + "plain.txt", info));
        Assert.True(server.UploadReached.Wait(TimeSpan.FromSeconds(10)), "upload-chunk に到達しませんでした");

        Task<NtStatus> flush2 = Task.Run(() => fs.FlushFileBuffers("\\" + "plain.txt", info));
        // 回帰: 進行中 persist の結果を待たずに即 Success を返してしまう
        Assert.False(flush2.Wait(300), "2 回目の flush が進行中の persist を待たずに完了しました");

        // ブロック解除 → 1 回目は失敗（FailNextUploads）、2 回目は再試行で成功
        server.UploadRelease.TrySetResult();
        Assert.True(flush1.Wait(TimeSpan.FromSeconds(10)));
        Assert.Equal(DokanResult.InternalError, flush1.Result);
        Assert.True(flush2.Wait(TimeSpan.FromSeconds(10)));
        Assert.Equal(DokanResult.Success, flush2.Result);

        // データは再試行で永続化されている
        byte[] chunk0 = E2eeCrypto.DecryptChunk(server.Chunks[0].Cipher, fileKey, 0, fileSalt, revision: 1);
        byte[] expected = plain[..ChunkSize];
        data.CopyTo(expected, 0);
        Assert.Equal(expected, chunk0);
    }

    // ---- F8: グローバル persist ゲート ----

    [Fact]
    public void 他ファイルの保存中も別ファイルの保存はブロックされない()
    {
        // 回帰: persist 直列化がファイルシステム全体のセマフォだったため、無関係な
        // ファイル B の persist がファイル A の通信終了までブロックされ、Dokan の
        // IRP タイムアウトに達する恐れがあった。直列化は同一 WriteState 内で十分。
        var server = new PlainServer();
        server.Files["a.txt"] = Pattern(100, seed: 100);
        server.Files["b.txt"] = Pattern(100, seed: 101);
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, Volume);

        var wsA = new CistaNasFileSystem.PlainRangeWriteState(fs, "a.txt", "a.txt", existingLength: 100);
        var wsB = new CistaNasFileSystem.PlainRangeWriteState(fs, "b.txt", "b.txt", existingLength: 100);
        wsA.Write(Pattern(10, seed: 110), 0, 10, 0);
        wsB.Write(Pattern(10, seed: 111), 0, 10, 0);

        // A の persist をサーバー側でブロック
        server.BlockNames.Add("a.txt");
        Task taskA = Task.Run(() => fs.UploadWriteState(wsA));
        Assert.True(server.BlockReached.Wait(TimeSpan.FromSeconds(10)), "A の persist に到達しませんでした");

        // B の persist は A と無関係なので完了する
        Task taskB = Task.Run(() => fs.UploadWriteState(wsB));
        Assert.True(taskB.Wait(TimeSpan.FromSeconds(5)), "無関係なファイル B の persist が A に阻塞されました");

        server.BlockRelease = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        server.BlockRelease.TrySetResult();
        Assert.True(taskA.Wait(TimeSpan.FromSeconds(10)));

        // B は既存 100B への部分書き込み（PATCH）で長さは変わらない
        Assert.Equal(100, server.Files["b.txt"].Length);
    }
}
