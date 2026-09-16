using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using CistaNAS.Client;
using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;
using DokanNet;

namespace CistaNAS.Tests;

/// <summary>
/// Dokan 書き込みパス round 5 の回帰テスト。
/// - H1: FileMode.Create（CREATE_ALWAYS）が既存内容を切り詰めない（plain / E2EE）
/// - H2: FileMode.Truncate（TRUNCATE_EXISTING）が未処理でハンドルが使えない
/// - H3: 非 E2EE の FileMode.CreateNew が存在チェックなしで上書きする
/// - H4: WriteState ハンドル経路の読み取りに DeclaredSize / EOF クランプが無く
///        切り詰め後の隙間読み取りで旧サーバー内容が復活する
/// </summary>
public class WritePathRound5Tests
{
    private const int ChunkSize = 4096;
    private const string Volume = "vol";

    private static byte[] Pattern(int len, int seed = 0)
        => Enumerable.Range(0, len).Select(i => (byte)((i + seed) % 251)).ToArray();

    private const DokanNet.FileAccess WriteAccess =
        DokanNet.FileAccess.WriteData | DokanNet.FileAccess.GenericWrite;

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
    /// 非 E2EE 複数ファイルの内容を保持する Fake。一覧 GET（存在チェック用）を含む。
    /// </summary>
    private sealed class PlainServer : HttpMessageHandler
    {
        public Dictionary<string, byte[]> Files { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string path = request.RequestUri!.AbsolutePath;
            var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);

            // 一覧 GET /api/v1/files/{vol}/（CreateNew / Create / Truncate の存在チェックが使う）
            if (request.Method == HttpMethod.Get && segments.Length == 4 && path.EndsWith('/'))
            {
                var payload = new
                {
                    files = Files.Select(kv => new
                    {
                        name = kv.Key,
                        length = kv.Value.Length,
                        createdAt = "2026-01-01T00:00:00Z",
                        modifiedAt = "2026-01-01T00:00:00Z",
                    }),
                };
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(payload),
                        System.Text.Encoding.UTF8, "application/json"),
                });
            }

            // /api/v1/files/{vol}/{name}
            string name = segments[^1];

            if (request.Method == HttpMethod.Post)
            {
                Files[name] = request.Content!.ReadAsByteArrayAsync(ct).GetAwaiter().GetResult();
                return Meta(name);
            }

            if (request.Method == HttpMethod.Patch)
            {
                long offset = long.Parse(request.RequestUri.Query.Replace("?offset=", ""));
                byte[] data = request.Content!.ReadAsByteArrayAsync(ct).GetAwaiter().GetResult();
                byte[] content = Files.TryGetValue(name, out var existing) ? existing : Array.Empty<byte>();
                int newLength = (int)Math.Max(content.Length, offset + data.Length);
                byte[] updated = new byte[newLength];
                content.CopyTo(updated, 0);
                data.CopyTo(updated, (int)offset);
                Files[name] = updated;
                return Meta(name);
            }

            if (request.Method == HttpMethod.Get)
            {
                byte[] content = Files.TryGetValue(name, out var existing) ? existing : Array.Empty<byte>();
                // Range ヘッダー（DownloadFileRangeAsync）を処理する
                var range = request.Headers.Range?.Ranges.FirstOrDefault();
                if (range is { } r)
                {
                    long from = r.From ?? 0;
                    if (from >= content.Length)
                        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.RequestedRangeNotSatisfiable));
                    int len = (int)Math.Min(content.Length - from, (r.To ?? content.Length - 1) - from + 1);
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(content[(int)from..((int)from + len)]),
                    });
                }
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

    /// <summary>
    /// 既存 E2EE ファイル 1 つ + 新規作成（create-file）を模倣する Fake。
    /// finalize の chunkCount でチャンクを論理切り詰めする。
    /// </summary>
    private sealed class FakeE2eeServer(byte[] masterKey, byte[] plain, byte[] fileKey, byte[] fileSalt) : HttpMessageHandler
    {
        public const string FileId = "f1";

        public Dictionary<int, (byte[] Cipher, int Revision)> Chunks { get; } = new();
        public List<(long EncryptedLength, int? ChunkCount)> FinalizeRequests { get; } = new();
        public int ChunkCount { get; private set; }
        public int CreateFileCount { get; private set; }

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

    // ---- H1 (plain): FileMode.Create は既存内容を切り詰める ----

    [Fact]
    public void 非E2EE_Createによる上書きは旧内容を切り詰める()
    {
        // 回帰 (H1): CREATE_ALWAYS なのに既存長を保持して開くため、小さいファイルで
        // 上書きすると旧内容の末尾が残り、サイズも旧長のままになっていた。
        var server = new PlainServer();
        server.Files["a.txt"] = Pattern(10000, seed: 210);
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, Volume);

        byte[] data = Pattern(100, seed: 211);
        var info = new StubFileInfo();
        Assert.Equal(DokanResult.Success,
            fs.CreateFile("\\a.txt", WriteAccess, FileShare.Read, FileMode.Create, FileOptions.None, FileAttributes.Normal, info));

        // オープン時点で切り詰め済み（サイズ 0 として見える）
        Assert.Equal(DokanResult.Success, fs.GetFileInformation("\\a.txt", out var fi, info));
        Assert.Equal(0, fi.Length);

        Assert.Equal(DokanResult.Success, fs.WriteFile("\\a.txt", data, out _, 0, info));
        fs.Cleanup("\\a.txt", info);

        byte[] content = server.Files["a.txt"];
        Assert.Equal(data, content); // 旧内容の末尾が残っていない
    }

    [Fact]
    public void 非E2EE_Createの無書き込みクローズで空ファイルになる()
    {
        var server = new PlainServer();
        server.Files["a.txt"] = Pattern(100, seed: 220);
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, Volume);

        var info = new StubFileInfo();
        Assert.Equal(DokanResult.Success,
            fs.CreateFile("\\a.txt", WriteAccess, FileShare.Read, FileMode.Create, FileOptions.None, FileAttributes.Normal, info));
        fs.Cleanup("\\a.txt", info);

        Assert.Empty(server.Files["a.txt"]);
    }

    // ---- H2 (plain): FileMode.Truncate ----

    [Fact]
    public void 非E2EE_Truncateは切り詰め書き込みハンドルを返す()
    {
        // 回帰 (H2): TRUNCATE_EXISTING が未処理で null Context のまま Success を返し、
        // 以降の書き込みが AccessDenied になっていた。
        var server = new PlainServer();
        server.Files["a.txt"] = Pattern(10000, seed: 230);
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, Volume);

        byte[] data = Pattern(50, seed: 231);
        var info = new StubFileInfo();
        Assert.Equal(DokanResult.Success,
            fs.CreateFile("\\a.txt", WriteAccess, FileShare.Read, FileMode.Truncate, FileOptions.None, FileAttributes.Normal, info));
        Assert.IsType<CistaNasFileSystem.PlainRangeWriteState>(info.Context);

        Assert.Equal(DokanResult.Success, fs.WriteFile("\\a.txt", data, out _, 0, info));
        fs.Cleanup("\\a.txt", info);

        Assert.Equal(data, server.Files["a.txt"]);
    }

    [Fact]
    public void 非E2EE_Truncateは存在しないファイルでFileNotFound()
    {
        var server = new PlainServer();
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, Volume);

        var info = new StubFileInfo();
        Assert.Equal(DokanResult.FileNotFound,
            fs.CreateFile("\\nope.txt", WriteAccess, FileShare.Read, FileMode.Truncate, FileOptions.None, FileAttributes.Normal, info));
        Assert.Null(info.Context);
    }

    // ---- H3 (plain): FileMode.CreateNew の存在チェック ----

    [Fact]
    public void 非E2EE_CreateNewは既存ファイルでFileExists()
    {
        // 回帰 (H3): 存在チェック無しで既存ファイルを黙って上書きしていた。
        var server = new PlainServer();
        server.Files["a.txt"] = Pattern(100, seed: 240);
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, Volume);

        var info = new StubFileInfo();
        Assert.Equal(DokanResult.FileExists,
            fs.CreateFile("\\a.txt", WriteAccess, FileShare.Read, FileMode.CreateNew, FileOptions.None, FileAttributes.Normal, info));
        Assert.Null(info.Context);
        // 既存内容は無傷
        Assert.Equal(100, server.Files["a.txt"].Length);
    }

    [Fact]
    public void 非E2EE_CreateNewは未存在ファイルで成功する()
    {
        var server = new PlainServer();
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, Volume);

        byte[] data = Pattern(80, seed: 241);
        var info = new StubFileInfo();
        Assert.Equal(DokanResult.Success,
            fs.CreateFile("\\b.txt", WriteAccess, FileShare.Read, FileMode.CreateNew, FileOptions.None, FileAttributes.Normal, info));
        Assert.NotNull(info.Context);

        Assert.Equal(DokanResult.Success, fs.WriteFile("\\b.txt", data, out _, 0, info));
        fs.Cleanup("\\b.txt", info);
        Assert.Equal(data, server.Files["b.txt"]);
    }

    // ---- H4 (plain): WriteState ハンドル経路の読み取りクランプ ----

    [Fact]
    public void 非E2EE_切り詰め後の読み取りはEOFで短縮され旧内容を返さない()
    {
        // 回帰 (H4): DeclaredSize クランプが無く、切り詰め点を越える読み取りで
        // 旧サーバー内容がそのまま返されていた（persist は切り詰め後の内容を確定させる）。
        var server = new PlainServer();
        server.Files["a.txt"] = Pattern(10000, seed: 250);
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, Volume);

        var info = new StubFileInfo();
        Assert.Equal(DokanResult.Success,
            fs.CreateFile("\\a.txt", WriteAccess, FileShare.Read, FileMode.Open, FileOptions.None, FileAttributes.Normal, info));
        Assert.Equal(DokanResult.Success, fs.SetEndOfFile("\\a.txt", 5000, info));

        byte[] buf = new byte[2000];
        Assert.Equal(DokanResult.Success, fs.ReadFile("\\a.txt", buf, out int bytesRead, 4000, info));

        // [4000,5000) は旧サーバー内容、EOF(5000) で短縮される
        Assert.Equal(1000, bytesRead);
        byte[] expected = Pattern(10000, seed: 250)[4000..5000];
        Assert.Equal(expected, buf[..1000]);

        // EOF 以降の読み取りは 0 バイト
        Assert.Equal(DokanResult.Success, fs.ReadFile("\\a.txt", buf, out int eofRead, 5000, info));
        Assert.Equal(0, eofRead);
    }

    [Fact]
    public void 非E2EE_切り詰め拡張の隙間読み取りはゼロを返す()
    {
        var server = new PlainServer();
        server.Files["a.txt"] = Pattern(10000, seed: 260);
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, Volume);

        byte[] data = Pattern(100, seed: 261);
        var info = new StubFileInfo();
        Assert.Equal(DokanResult.Success,
            fs.CreateFile("\\a.txt", WriteAccess, FileShare.Read, FileMode.Open, FileOptions.None, FileAttributes.Normal, info));
        Assert.Equal(DokanResult.Success, fs.SetEndOfFile("\\a.txt", 5000, info));
        Assert.Equal(DokanResult.Success, fs.WriteFile("\\a.txt", data, out _, 6000, info));

        // [5900,6200) を読む: [5900,6000) 隙間ゼロ + [6000,6100) 書き込み + EOF(6100) で短縮
        byte[] buf = new byte[300];
        Assert.Equal(DokanResult.Success, fs.ReadFile("\\a.txt", buf, out int bytesRead, 5900, info));
        Assert.Equal(200, bytesRead);
        Assert.True(buf[..100].All(b => b == 0), "隙間に旧内容が復活しています");
        Assert.Equal(data, buf[100..200]);
    }

    // ---- H1 (E2EE): FileMode.Create は finalize で切り詰める ----

    [Fact]
    public void E2EE_Createによる上書きはfinalizeでチャンクを切り詰める()
    {
        // 回帰 (H1): CREATE_ALWAYS なのに既存 3 チャンクが残り、サーバー上に旧内容の末尾が
        // 生きたまま（暗号化チャンクとして）になっていた。
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] fileSalt = RandomNumberGenerator.GetBytes(16);
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        var server = new FakeE2eeServer(masterKey, Pattern(10000, seed: 270), fileKey, fileSalt).Init();
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, masterKey, Volume, chunkSize: ChunkSize);

        byte[] data = Pattern(100, seed: 271);
        var info = new StubFileInfo();
        Assert.Equal(DokanResult.Success,
            fs.CreateFile("\\plain.txt", WriteAccess, FileShare.Read, FileMode.Create, FileOptions.None, FileAttributes.Normal, info));

        // オープン時点で切り詰め済み
        Assert.Equal(DokanResult.Success, fs.GetFileInformation("\\plain.txt", out var fi, info));
        Assert.Equal(0, fi.Length);

        Assert.Equal(DokanResult.Success, fs.WriteFile("\\plain.txt", data, out _, 0, info));
        fs.Cleanup("\\plain.txt", info);

        // finalize が chunkCount=1（100B）で確定し、旧チャンク 1-2 は論理削除される
        Assert.Equal((E2eeCrypto.ComputeEncryptedLength(100, ChunkSize), 1), server.FinalizeRequests[^1]);
        Assert.Equal(1, server.ChunkCount);

        byte[] chunk0 = E2eeCrypto.DecryptChunk(server.Chunks[0].Cipher, fileKey, 0, fileSalt, revision: 1);
        Assert.Equal(data, chunk0);
    }

    // ---- H2 (E2EE): FileMode.Truncate ----

    [Fact]
    public void E2EE_Truncateは存在しないファイルでFileNotFound()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] fileSalt = RandomNumberGenerator.GetBytes(16);
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        var server = new FakeE2eeServer(masterKey, Pattern(100, seed: 280), fileKey, fileSalt).Init();
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, masterKey, Volume, chunkSize: ChunkSize);

        var info = new StubFileInfo();
        Assert.Equal(DokanResult.FileNotFound,
            fs.CreateFile("\\nope.txt", WriteAccess, FileShare.Read, FileMode.Truncate, FileOptions.None, FileAttributes.Normal, info));
        Assert.Null(info.Context);
    }

    [Fact]
    public void E2EE_Truncateは無書き込みクローズで空ファイルに確定する()
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] fileSalt = RandomNumberGenerator.GetBytes(16);
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        var server = new FakeE2eeServer(masterKey, Pattern(10000, seed: 290), fileKey, fileSalt).Init();
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, masterKey, Volume, chunkSize: ChunkSize);

        var info = new StubFileInfo();
        Assert.Equal(DokanResult.Success,
            fs.CreateFile("\\plain.txt", WriteAccess, FileShare.Read, FileMode.Truncate, FileOptions.None, FileAttributes.Normal, info));
        Assert.NotNull(info.Context);
        fs.Cleanup("\\plain.txt", info);

        // 現行形式の空ファイルは salt 単独の chunk 0（1 チャンク）として確定される
        long emptyEncLength = E2eeCrypto.ComputeEncryptedLength(0, ChunkSize);
        Assert.Equal((emptyEncLength, E2eeCrypto.ComputeChunkCount(0, ChunkSize)), server.FinalizeRequests[^1]);
        Assert.Equal(E2eeCrypto.ComputeChunkCount(0, ChunkSize), server.ChunkCount);
    }
}
