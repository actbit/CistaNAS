using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using CistaNAS.Client;
using CistaNAS.Client.Api;

namespace CistaNAS.Tests;

/// <summary>
/// CistaNasFileSystem.UploadWriteState のテスト（Dokan ドライバ不要・HttpMessageHandler モック）。
/// Critical-3: 非E2EE 上書きで新ファイル削除を検証。
/// Critical-4: E2EE チャンクアップロード途中失敗時のロールバックを検証。
/// </summary>
public class DokanUploadWriteStateTests
{
    /// <summary>全リクエストを記録し 200 OK を返すモック。PATCH は FileMetadata JSON を返す。</summary>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        public List<(string Method, string Uri)> Requests { get; } = new();
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add((request.Method.Method, request.RequestUri!.ToString()!));
            // PATCH（差分書き込み）は FileMetadata JSON を期待する
            var content = request.Method.Method == "PATCH"
                ? new StringContent("{\"name\":\"file.txt\",\"length\":3,\"createdAt\":\"2026-01-01T00:00:00Z\",\"modifiedAt\":\"2026-01-01T00:00:00Z\"}", Encoding.UTF8, "application/json")
                : new StringContent("");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
        }
    }

    /// <summary>POST（全体アップロード）/ PATCH / GET（ダウンロード）で 1 ファイルの内容を保持するモック。</summary>
    private sealed class StatefulPlainFileHandler(byte[] initial) : HttpMessageHandler
    {
        public byte[] Content { get; private set; } = initial;
        public int PutCount { get; private set; }
        public int PatchCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Post)
            {
                Content = request.Content!.ReadAsByteArrayAsync(cancellationToken).GetAwaiter().GetResult();
                PutCount++;
                return Metadata();
            }
            if (request.Method == HttpMethod.Patch)
            {
                PatchCount++;
                return Metadata();
            }
            if (request.Method == HttpMethod.Get)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Content) });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private Task<HttpResponseMessage> Metadata() => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                $"{{\"name\":\"file.txt\",\"length\":{Content.Length},\"createdAt\":\"2026-01-01T00:00:00Z\",\"modifiedAt\":\"2026-01-01T00:00:00Z\"}}",
                Encoding.UTF8, "application/json"),
        });
    }

    /// <summary>create-file は fileId 応答、upload-chunk は 500 で失敗を注入するモック。</summary>
    private sealed class FailUploadChunkHandler : HttpMessageHandler
    {
        public List<(string Method, string Uri)> Requests { get; } = new();
        public const string CreatedFileId = "newfile123";
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!.ToString()!;
            Requests.Add((request.Method.Method, uri));
            if (uri.Contains("/write-lease", StringComparison.Ordinal))
            {
                if (request.Method == HttpMethod.Post && !uri.EndsWith("/renew", StringComparison.Ordinal))
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"token\":\"test-write-lease\"}", Encoding.UTF8, "application/json")
                    });
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
            }
            if (uri.Contains("upload-chunk"))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError));
            if (uri.Contains("create-file"))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        $"{{\"fileId\":\"{CreatedFileId}\",\"writeLeaseToken\":\"test-write-lease\"}}",
                        Encoding.UTF8, "application/json")
                });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("") });
        }
    }

    /// <summary>
    /// 非E2EE 既存ファイルの部分編集で、PATCH（差分書き込み）が呼ばれ DELETE は呼ばれないこと。
    /// Critical-3 整合: 差分保存では部分上書きで新ファイル削除は発生しない。
    /// </summary>
    [Fact]
    public void UploadWriteState_NonE2eePartialEdit_SendsPatch_NoDelete()
    {
        var handler = new RecordingHandler();
        var api = new CistaNasApiClient(new HttpClient(handler) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, "vol");

        var ws = new CistaNasFileSystem.PlainRangeWriteState(fs, "file.txt", "file.txt", existingLength: 100);
        ws.Write(new byte[] { 1, 2, 3 }, 0, 3, 0);

        fs.UploadWriteState(ws);

        // PATCH（差分）が呼ばれる
        Assert.Contains(handler.Requests, r => r.Method == "PATCH");
        // DELETE は呼ばれない
        Assert.DoesNotContain(handler.Requests, r => r.Method == "DELETE");
    }

    /// <summary>
    /// E2EE 新規ファイル作成時にチャンクアップロードが失敗した場合、作成中の fileId を削除（ロールバック）すること。
    /// Critical-4 整合: サーバーに孤児ファイルを残さない。
    /// </summary>
    [Fact]
    public void UploadWriteState_E2eeNewFileChunkFailure_RollsBackCreatedFile()
    {
        var handler = new FailUploadChunkHandler();
        var api = new CistaNasApiClient(new HttpClient(handler) { BaseAddress = new Uri("http://test/") });
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        var fs = new CistaNasFileSystem(api, masterKey, "vol");

        var ws = new CistaNasFileSystem.E2eeChunkWriteState(fs, "plain.txt", null);  // 新規ファイル
        ws.Write(RandomNumberGenerator.GetBytes(100), 0, 100, 0);

        // UploadChunk 失敗で例外（ロールバック後に再送）
        Assert.ThrowsAny<Exception>(() => fs.UploadWriteState(ws));

        // 作成中 fileId の DELETE（ロールバック）が呼ばれる
        Assert.Contains(handler.Requests,
            r => r.Method == "DELETE" && r.Uri.Contains(FailUploadChunkHandler.CreatedFileId));
    }

    /// <summary>
    /// 非E2EE 既存ファイルへの書き込み後に SetEndOfFile で切り詰めると、
    /// PATCH（長さを縮められない）ではなく全体 PUT で切り詰め後の内容が確定すること。
    /// 回帰: Write で進んだ _maxWritten が CurrentSize = Max(DeclaredSize, _maxWritten) で
    /// 切り詰めを握りつぶし、PATCH のみでファイルが切り詰め前の長さのまま残っていた。
    /// </summary>
    [Fact]
    public void UploadWriteState_NonE2eeTruncateAfterWrite_SendsFullPutWithShortenedContent()
    {
        byte[] existing = new byte[10000];
        for (int i = 0; i < existing.Length; i++) existing[i] = (byte)(i % 251);
        var handler = new StatefulPlainFileHandler(existing);
        var api = new CistaNasApiClient(new HttpClient(handler) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, "vol");

        var ws = new CistaNasFileSystem.PlainRangeWriteState(fs, "file.txt", "file.txt", existingLength: 10000);
        byte[] data = Enumerable.Range(0, 200).Select(i => (byte)(100 + i % 156)).ToArray();
        ws.Write(data, 0, data.Length, 100); // 100..300 を書き込み
        ws.SetDeclaredSize(5000);            // 同一ハンドル内での切り詰め

        // 回帰: 書き込み後の切り詰めが _maxWritten に握りつぶされないこと
        Assert.Equal(5000, ws.CurrentSize);

        fs.UploadWriteState(ws);

        // PATCH では長さを縮められないため、全体 PUT で確定する
        Assert.Equal(1, handler.PutCount);
        Assert.Equal(0, handler.PatchCount);
        Assert.Equal(5000, handler.Content.Length);

        // 内容: 既存 5000 バイトの切り詰め + 先頭付近の書き込みデータ
        byte[] expected = existing[..5000];
        data.CopyTo(expected, 100);
        Assert.Equal(expected, handler.Content);
    }
}
