using System.Net;
using System.Text;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;
using CistaNAS.Shared.Crypto;
using Xunit;

namespace CistaNAS.Tests;

/// <summary>
/// E2eeFileTransferService のチャンク暗号化ラウンドトリップ検証。
/// FakeE2eeServer でサーバーの /e2ee エンドポイントを模倣し、
/// 暗号文の保存 / 取得と write-lease ヘッダーの付与を確認する。
/// </summary>
public class E2eeTransferServiceTests
{
    private const string Volume = "vol";
    private static readonly byte[] MasterKey = E2eeCrypto.GenerateMasterKey();

    private static (E2eeFileTransferService Svc, FakeE2eeServer Server) CreateService(int chunkSize = 64 * 1024)
    {
        var server = new FakeE2eeServer();
        var http = new HttpClient(server) { BaseAddress = new Uri("http://test/") };
        var session = new E2eeSession();
        session.StoreKey(Volume, MasterKey, chunkSize);
        return (new E2eeFileTransferService(new CistaNasApiClient(http), session), server);
    }

    [Fact]
    public async Task アップロードからダウンロードへのラウンドトリップ()
    {
        (var svc, var server) = CreateService(chunkSize: 1024); // 小さいチャンクで複数チャンク化
        byte[] plain = Encoding.UTF8.GetBytes(new string('A', 2500)); // 3 チャンク (1024,1024,452)

        string fileId;
        int chunkCount;
        using (var input = new MemoryStream(plain))
        {
            (fileId, chunkCount) = await svc.UploadAsync(Volume, "test.bin", input, plain.Length);
        }

        Assert.Equal(3, chunkCount);
        Assert.Equal(3, server.GetChunkCount(fileId));

        var entry = new E2eeFileEntry
        {
            FileId = fileId,
            EncryptedName = "enc",
            EncryptedLength = plain.Length + E2eeCrypto.SaltSize + E2eeCrypto.GcmTagSize * chunkCount,
            ChunkCount = chunkCount,
        };

        using MemoryStream output = await svc.OpenDecryptedAsync(Volume, entry);
        Assert.Equal(plain, output.ToArray());
    }

    [Fact]
    public async Task アップロード時にwrite_leaseヘッダーが必須()
    {
        (var svc, var server) = CreateService();
        byte[] plain = [1, 2, 3];
        using var input = new MemoryStream(plain);
        (string fileId, _) = await svc.UploadAsync(Volume, "small.bin", input, plain.Length);

        // upload-chunk は lease ヘッダーなしでは 400 を返すFakeになっている
        Assert.All(server.ChunkLeaseHeaders.Values, t => Assert.False(string.IsNullOrEmpty(t)));
    }

    [Fact]
    public async Task 暗号化チャンクは平文と一致しない()
    {
        (var svc, var server) = CreateService();
        byte[] plain = Encoding.UTF8.GetBytes("secret-content");
        using var input = new MemoryStream(plain);
        (string fileId, _) = await svc.UploadAsync(Volume, "sec.txt", input, plain.Length);

        using var http = new HttpClient(server) { BaseAddress = new Uri("http://test/") };
        byte[] enc0 = await http.GetByteArrayAsync($"/api/v1/e2ee/{Volume}/download-chunk/{fileId}/0");
        Assert.NotEqual(plain, enc0);
        // chunk 0 は先頭に fileSalt (16B) を含むため平文より長い
        Assert.True(enc0.Length > plain.Length);
    }

    [Fact]
    public void ファイル名の暗号化ラウンドトリップと誤鍵失敗()
    {
        string enc = E2eeCrypto.EncryptFilename("写真.jpg", MasterKey);
        Assert.Equal("写真.jpg", E2eeCrypto.DecryptFilename(enc, MasterKey));
        byte[] wrongKey = E2eeCrypto.GenerateMasterKey();
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => E2eeCrypto.DecryptFilename(enc, wrongKey));
        Assert.Null(E2eeFileTransferService.TryDecryptName(enc, wrongKey));
    }

    [Fact]
    public void 平文長計算()
    {
        var entry = new E2eeFileEntry { FileId = "f", EncryptedName = "e", EncryptedLength = 100 + 16 + 16 * 2, ChunkCount = 2 };
        Assert.Equal(100, E2eeFileTransferService.ComputePlainLength(entry));
    }

    /// <summary>
    /// 回帰: Dokan 差分保存で再暗号化されたチャンク（revision >= 1）は nonce 導出に revision が混入する。
    /// DownloadAsync が revision を無視して revision=0 で復号すると CryptographicException で開けなくなる。
    /// </summary>
    [Fact]
    public async Task Dokan編集済みrevision付きチャンクを復号できる()
    {
        (var svc, var server) = CreateService(chunkSize: 1024);
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(MasterKey, fileSalt);
        byte[] plain0 = new byte[1024];
        Array.Fill(plain0, (byte)0x5A);
        byte[] plain1 = Encoding.UTF8.GetBytes("edited via dokan mount");

        byte[] enc0 = E2eeCrypto.EncryptChunk(plain0, fileKey, 0, fileSalt, isFirstChunk: true, revision: 0);
        byte[] enc1 = E2eeCrypto.EncryptChunk(plain1, fileKey, 1, fileSalt, isFirstChunk: false, revision: 1);

        // nonce に revision が効いていることの確認（revision 0 ではチャンク 1 は復号失敗）
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => E2eeCrypto.DecryptChunk(enc1, fileKey, 1, fileSalt, revision: 0));

        string fileId = server.SeedFile((0, enc0, 0), (1, enc1, 1));
        var entry = new E2eeFileEntry
        {
            FileId = fileId,
            EncryptedName = "enc",
            EncryptedLength = plain0.Length + plain1.Length + E2eeCrypto.SaltSize + E2eeCrypto.GcmTagSize * 2,
            ChunkCount = 2,
        };

        using MemoryStream output = await svc.OpenDecryptedAsync(Volume, entry);
        byte[] expected = [.. plain0, .. plain1];
        Assert.Equal(expected, output.ToArray());
    }
}

/// <summary>E2EE チャンク転送エンドポイントのインメモリFake。</summary>
internal sealed class FakeE2eeServer : HttpMessageHandler
{
    private readonly Dictionary<(string FileId, int Index), byte[]> _chunks = new();
    private readonly Dictionary<(string FileId, int Index), int> _revisions = new();
    private readonly Dictionary<(string FileId, int Index), string> _leaseHeaders = new();
    private int _nextFileId = 1;

    public Dictionary<(string FileId, int Index), string> ChunkLeaseHeaders => _leaseHeaders;

    public int GetChunkCount(string fileId) => _chunks.Keys.Count(k => k.FileId == fileId);

    /// <summary>指定 revision で暗号化済みのチャンクを直接シードする（Dokan 差分保存済みファイルの再現用）。</summary>
    public string SeedFile(params (int Index, byte[] Data, int Revision)[] chunks)
    {
        string fileId = $"seed{_nextFileId++}";
        foreach (var (index, data, revision) in chunks)
        {
            _chunks[(fileId, index)] = data;
            _revisions[(fileId, index)] = revision;
        }
        return fileId;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        string path = request.RequestUri!.AbsolutePath;
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);

        // /api/v1/e2ee/{vol}/...
        if (segments.Length >= 4 && segments[2] == "e2ee")
        {
            string op = segments[4];

            if (op == "create-file" && request.Method == HttpMethod.Post)
                return Task.FromResult(Json(HttpStatusCode.Created, $$"""{"fileId":"f{{_nextFileId++}}","writeLeaseToken":"lease-1"}"""));

            if (op == "upload-chunk" && request.Method == HttpMethod.Post)
            {
                string lease = request.Headers.TryGetValues("X-CistaNAS-Write-Lease", out var vals) ? vals.First() : "";
                if (string.IsNullOrEmpty(lease))
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest));
                string fileId = segments[5];
                int index = int.Parse(segments[6]);
                _leaseHeaders[(fileId, index)] = lease;
                _chunks[(fileId, index)] = request.Content!.ReadAsByteArrayAsync(ct).GetAwaiter().GetResult();
                _revisions[(fileId, index)] = 0;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
            }

            if (op == "download-chunk" && request.Method == HttpMethod.Get)
            {
                string fileId = segments[5];
                int index = int.Parse(segments[6]);
                if (!_chunks.TryGetValue((fileId, index), out var data))
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
                var res = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(data) };
                res.Headers.Add("X-Chunk-Revision", _revisions.GetValueOrDefault((fileId, index)).ToString());
                return Task.FromResult(res);
            }

            if (op == "finalize-file" && request.Method == HttpMethod.Patch)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));

            if (op == "files" && request.Method == HttpMethod.Delete)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));

            if (op == "write-lease" && request.Method == HttpMethod.Delete)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
        }

        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }

    private static HttpResponseMessage Json(HttpStatusCode code, string json) => new(code)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json"),
    };
}
