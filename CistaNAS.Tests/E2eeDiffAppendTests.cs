using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Client;
using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// E2eeChunkWriteState の既存ファイル差分保存（UploadE2eeDiff）における
/// 末尾チャンク追記・範囲超過書き込みのデータ整合性テスト。
/// 回帰: 一部が埋まった既存末尾チャンクをまたぐ追記で copyLen=0 になり、
/// 追記データがゼロ埋めされて消失する問題（サイレントデータロス）。
/// </summary>
public class E2eeDiffAppendTests
{
    private const int ChunkSize = 4096;
    private const string Volume = "vol";
    private const string PlainName = "plain.txt";

    /// <summary>
    /// 既存 E2EE ファイル 1 つを持ち、UploadE2eeDiff に必要なエンドポイント
    /// (list / write-lease / download-chunk / chunk-hash / upload-chunk / finalize) を模倣する Fake。
    /// diff アップロードされた暗号文を UploadedChunks に記録する。
    /// </summary>
    private sealed class FakeExistingE2eeFileServer(byte[] masterKey, byte[] plain, byte[] fileKey, byte[] fileSalt) : HttpMessageHandler
    {
        public const string FileId = "f1";

        /// <summary>差分アップロードされた暗号文（チャンクインデックス → 暗号文）。</summary>
        public Dictionary<int, byte[]> UploadedChunks { get; } = new();

        /// <summary>upload-chunk リクエストの総数（再送検出用）。</summary>
        public int UploadCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string path = request.RequestUri!.AbsolutePath;
            var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            string op = segments.Length >= 5 ? segments[4] : "";

            if (op == "files" && request.Method == HttpMethod.Get && segments.Length == 5)
            {
                int chunkCount = (plain.Length + ChunkSize - 1) / ChunkSize;
                string encName = E2eeCrypto.EncryptFilename(PlainName, masterKey);
                long encLength = E2eeCrypto.SaltSize + plain.Length + (long)E2eeCrypto.GcmTagSize * chunkCount;
                var payload = new
                {
                    files = new[]
                    {
                        new
                        {
                            fileId = FileId,
                            encryptedName = encName,
                            encryptedLength = encLength,
                            chunkCount,
                            createdAt = "2026-01-01T00:00:00Z",
                            modifiedAt = "2026-01-01T00:00:00Z",
                        },
                    },
                };
                return JsonR(HttpStatusCode.OK, JsonSerializer.Serialize(payload));
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

            if (op == "download-chunk" && request.Method == HttpMethod.Get)
            {
                int index = int.Parse(segments[6]);
                int len = Math.Min(ChunkSize, plain.Length - index * ChunkSize);
                byte[] enc = E2eeCrypto.EncryptChunk(
                    plain[(index * ChunkSize)..(index * ChunkSize + len)], fileKey, index, fileSalt,
                    isFirstChunk: index == 0);
                var res = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(enc) };
                res.Headers.Add("X-Chunk-Revision", "0");
                return Task.FromResult(res);
            }

            if (op == "chunk-hash" && request.Method == HttpMethod.Get)
                return JsonR(HttpStatusCode.OK, """{"hash":"fake-hash","revision":0}""");

            if (op == "upload-chunk" && request.Method == HttpMethod.Post)
            {
                int index = int.Parse(segments[6]);
                UploadedChunks[index] = request.Content!.ReadAsByteArrayAsync(ct).GetAwaiter().GetResult();
                UploadCount++;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
            }

            if (op == "finalize-file" && request.Method == HttpMethod.Patch)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static Task<HttpResponseMessage> JsonR(HttpStatusCode code, string json) => Task.FromResult(new HttpResponseMessage(code)
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json"),
        });
    }

    private static (CistaNasFileSystem Fs, FakeExistingE2eeFileServer Server, byte[] FileSalt, byte[] FileKey, byte[] Plain)
        CreateExistingFile(int plainLength)
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] plain = new byte[plainLength];
        for (int i = 0; i < plainLength; i++) plain[i] = (byte)(i % 251);
        byte[] fileSalt = RandomNumberGenerator.GetBytes(16);
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);

        var server = new FakeExistingE2eeFileServer(masterKey, plain, fileKey, fileSalt);
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, masterKey, Volume, chunkSize: ChunkSize);
        return (fs, server, fileSalt, fileKey, plain);
    }

    [Fact]
    public void 既存末尾チャンクをまたぐ追記で追記データが消失しない()
    {
        // 5000 バイト = 4096 + 904。末尾チャンク（904B）に 100B を追記する。
        var (fs, server, fileSalt, fileKey, plain) = CreateExistingFile(5000);
        byte[] append = Enumerable.Range(0, 100).Select(i => (byte)(200 + i % 50)).ToArray();

        var ws = new CistaNasFileSystem.E2eeChunkWriteState(fs, PlainName, FakeExistingE2eeFileServer.FileId);
        try
        {
            ws.Write(append, 0, append.Length, 5000);
            fs.UploadWriteState(ws);
        }
        finally { ws.Dispose(); }

        // 未変更チャンクは差分保存で再アップロードされない
        Assert.DoesNotContain(0, server.UploadedChunks.Keys);
        Assert.True(server.UploadedChunks.TryGetValue(1, out byte[]? uploaded));

        // revision 1 で再暗号化されたチャンクが復号でき、追記データが保持されている
        byte[] expected = [.. plain[ChunkSize..], .. append];
        byte[] decrypted = E2eeCrypto.DecryptChunk(uploaded!, fileKey, 1, fileSalt, revision: 1);
        Assert.Equal(expected, decrypted);

        // nonce に revision が効いていることの確認（revision 0 では復号失敗）
        Assert.ThrowsAny<CryptographicException>(
            () => E2eeCrypto.DecryptChunk(uploaded!, fileKey, 1, fileSalt, revision: 0));
    }

    [Fact]
    public void 既存末尾チャンクの終端をまたぐ上書きでデータが消失しない()
    {
        // 4950〜5049 に書き込み: 旧末尾チャンク終端 (5000) をまたぐ
        var (fs, server, fileSalt, fileKey, plain) = CreateExistingFile(5000);
        byte[] overwrite = Enumerable.Range(0, 100).Select(i => (byte)(100 + i % 80)).ToArray();

        var ws = new CistaNasFileSystem.E2eeChunkWriteState(fs, PlainName, FakeExistingE2eeFileServer.FileId);
        try
        {
            ws.Write(overwrite, 0, overwrite.Length, 4950);
            fs.UploadWriteState(ws);
        }
        finally { ws.Dispose(); }

        Assert.True(server.UploadedChunks.TryGetValue(1, out byte[]? uploaded));
        byte[] expected = [.. plain[ChunkSize..4950], .. overwrite];
        byte[] decrypted = E2eeCrypto.DecryptChunk(uploaded!, fileKey, 1, fileSalt, revision: 1);
        Assert.Equal(expected, decrypted);
    }

    [Fact]
    public void ファイル終端を超えるsparse書き込みで隙間がゼロ埋めされる()
    {
        // 5200〜5249 に書き込み: 旧末尾 (5000) から 200 バイトの隙間
        var (fs, server, fileSalt, fileKey, plain) = CreateExistingFile(5000);
        byte[] data = Enumerable.Range(0, 50).Select(i => (byte)(i + 1)).ToArray();

        var ws = new CistaNasFileSystem.E2eeChunkWriteState(fs, PlainName, FakeExistingE2eeFileServer.FileId);
        try
        {
            ws.Write(data, 0, data.Length, 5200);
            fs.UploadWriteState(ws);
        }
        finally { ws.Dispose(); }

        Assert.True(server.UploadedChunks.TryGetValue(1, out byte[]? uploaded));
        byte[] expected = new byte[5200 + data.Length - ChunkSize];
        plain[ChunkSize..].CopyTo(expected, 0);
        data.CopyTo(expected, 5200 - ChunkSize);
        byte[] decrypted = E2eeCrypto.DecryptChunk(uploaded!, fileKey, 1, fileSalt, revision: 1);
        Assert.Equal(expected, decrypted);
    }

    [Fact]
    public void 永続化済みチャンクは次回の差分保存で再送されない()
    {
        // 回帰: アップロード済みダーティチャンクを保持し続けると、WriteFile のたびに
        // 全蓄積チャンクが再送され転送量が O(N²) に膨らむ。永続化済みチャンクは
        // 解放し、2 回目の保存では新規ダーティチャンクだけを送る。
        var (fs, server, fileSalt, fileKey, plain) = CreateExistingFile(5000);
        byte[] write1 = Enumerable.Range(0, 100).Select(i => (byte)(10 + i)).ToArray();
        byte[] write2 = Enumerable.Range(0, 100).Select(i => (byte)(200 + i)).ToArray();

        var ws = new CistaNasFileSystem.E2eeChunkWriteState(fs, PlainName, FakeExistingE2eeFileServer.FileId);
        try
        {
            ws.Write(write1, 0, write1.Length, 0);
            fs.UploadWriteState(ws);

            // 1 回目: チャンク 0 のみ送信
            Assert.Equal(1, server.UploadCount);
            Assert.Equal([0], server.UploadedChunks.Keys);

            ws.Write(write2, 0, write2.Length, ChunkSize);
            fs.UploadWriteState(ws);
        }
        finally { ws.Dispose(); }

        // 2 回目: 新規ダーティのチャンク 1 のみが送られ、永続化済みチャンク 0 は再送されない
        Assert.Equal(2, server.UploadCount);
        Assert.Equal([0, 1], server.UploadedChunks.Keys);

        byte[] expected = [.. write2, .. plain[4196..]];
        byte[] decrypted = E2eeCrypto.DecryptChunk(server.UploadedChunks[1], fileKey, 1, fileSalt, revision: 1);
        Assert.Equal(expected, decrypted);
    }

    /// <summary>
    /// サーバー側状態（チャンク数・チャンクごとの revision・暗号文）を追跡する Fake。
    /// upload-chunk は実サーバー（E2eeFileService）と同じ規則で revision を進める:
    /// 置換（index が既存チャンク数未満）は rev+1、追記（index == 既存チャンク数）は rev 0。
    /// chunk-hash は未アップロードのチャンクに対して 404 を返す。
    /// </summary>
    private sealed class FakeStatefulE2eeServer(byte[] masterKey, byte[] plain, byte[] fileKey, byte[] fileSalt) : HttpMessageHandler
    {
        public const string FileId = "f1";

        /// <summary>サーバーに保存済みのチャンク（暗号文, revision）。</summary>
        public Dictionary<int, (byte[] Cipher, int Revision)> Chunks { get; } = new();

        /// <summary>サーバーが記録しているチャンク数（追記で拡張、truncate で縮小）。</summary>
        public int ChunkCount { get; private set; }

        /// <summary>初期平文をチャンク分割してサーバー状態を初期化する。</summary>
        public FakeStatefulE2eeServer Init()
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

            if (op == "files" && request.Method == HttpMethod.Get && segments.Length == 5)
            {
                string encName = E2eeCrypto.EncryptFilename(PlainName, masterKey);
                long encLength = E2eeCrypto.SaltSize + plain.Length + (long)E2eeCrypto.GcmTagSize * Chunks.Count;
                var payload = new
                {
                    files = new[]
                    {
                        new
                        {
                            fileId = FileId,
                            encryptedName = encName,
                            encryptedLength = encLength,
                            chunkCount = ChunkCount,
                            createdAt = "2026-01-01T00:00:00Z",
                            modifiedAt = "2026-01-01T00:00:00Z",
                        },
                    },
                };
                return JsonR(HttpStatusCode.OK, JsonSerializer.Serialize(payload));
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
                byte[] cipher = request.Content!.ReadAsByteArrayAsync(ct).GetAwaiter().GetResult();
                bool isReplace = index < ChunkCount && Chunks.ContainsKey(index);
                int revision = isReplace ? Chunks[index].Revision + 1 : 0;
                Chunks[index] = (cipher, revision);
                if (index >= ChunkCount) ChunkCount = index + 1; // 末尾追記: チャンクを拡張
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
            }

            if (op == "finalize-file" && request.Method == HttpMethod.Patch)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static Task<HttpResponseMessage> JsonR(HttpStatusCode code, string json) => Task.FromResult(new HttpResponseMessage(code)
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json"),
        });
    }

    [Fact]
    public void 同一ハンドル内で追記したチャンクは次回保存でゼロ上書きされずrevisionも一致する()
    {
        // 回帰 1: ClearPersistedChunks 後も _existingChunkCount が handle-open 時点で凍結され、
        //   同一ハンドル内で追記アップロードしたチャンクが「未存在」扱いになって全ゼロで
        //   再アップロードされ、永続化データがサイレントに破壊される。
        // 回帰 2: 追記チャンクの 2 回目以降の置換が rev 0 で暗号化され、サーバー記録の
        //   revision（rev+1）と食い違って復号不能になる（ノンス再利用にもなる）。
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        byte[] plain = new byte[3000];
        for (int i = 0; i < plain.Length; i++) plain[i] = (byte)(i % 251);
        byte[] fileSalt = RandomNumberGenerator.GetBytes(16);
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);

        var server = new FakeStatefulE2eeServer(masterKey, plain, fileKey, fileSalt).Init();
        var api = new CistaNasApiClient(new HttpClient(server) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, masterKey, Volume, chunkSize: ChunkSize);

        byte[] append = Enumerable.Range(0, 2000).Select(i => (byte)(50 + i % 200)).ToArray();
        byte[] patch = Enumerable.Range(0, 100).Select(i => (byte)(220 + i % 30)).ToArray();

        var ws = new CistaNasFileSystem.E2eeChunkWriteState(fs, PlainName, FakeStatefulE2eeServer.FileId);
        try
        {
            // 1 回目の persist: 3000..5000 への追記でチャンク 0（置換）とチャンク 1（追記 rev 0）を送る
            ws.Write(append, 0, append.Length, 3000);
            fs.UploadWriteState(ws);

            Assert.Equal(2, server.ChunkCount);
            Assert.Equal(0, server.Chunks[1].Revision);

            // 永続化済みチャンク解放後の 2 回目の書き込み: 追記済みチャンク 1 内を部分更新
            ws.Write(patch, 0, patch.Length, 4500);
            fs.UploadWriteState(ws);
        }
        finally { ws.Dispose(); }

        // サーバー記録 revision は rev+1。クライアントが同じ revision で暗号化している前提で
        // 復号できること（回帰 2: 食い違うとタグ検証が失敗する）
        Assert.Equal(1, server.Chunks[1].Revision);
        byte[] decrypted = E2eeCrypto.DecryptChunk(server.Chunks[1].Cipher, fileKey, 1, fileSalt, revision: 1);
        Assert.ThrowsAny<CryptographicException>(
            () => E2eeCrypto.DecryptChunk(server.Chunks[1].Cipher, fileKey, 1, fileSalt, revision: 0));

        // チャンク 1 の内容: 追記データ（RMW でサーバーから再取得）に 2 回目の書き込みを反映。
        // 回帰 1: 凍結された _existingChunkCount のせいでゼロバッファが再アップロードされると破綻する
        byte[] expected = append[(ChunkSize - 3000)..].ToArray();
        patch.CopyTo(expected, 4500 - ChunkSize);
        Assert.Equal(expected, decrypted);
    }
}
