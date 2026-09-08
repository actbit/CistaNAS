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
}
