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
    /// <summary>全リクエストを記録し 200 OK を返すモック。</summary>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        public List<(string Method, string Uri)> Requests { get; } = new();
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add((request.Method.Method, request.RequestUri!.ToString()!));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("")
            });
        }
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
            if (uri.Contains("upload-chunk"))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError));
            if (uri.Contains("create-file"))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent($"{{\"fileId\":\"{CreatedFileId}\"}}", Encoding.UTF8, "application/json")
                });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("") });
        }
    }

    /// <summary>
    /// 非E2EE 上書き（ExistingFileId == PlainName）で、アップロード後に削除 API を呼ばないこと。
    /// 修正前は同名 upsert 後に DELETE して新ファイルを消去していた（Critical-3）。
    /// </summary>
    [Fact]
    public void UploadWriteState_NonE2eeOverwrite_DoesNotDeleteUploadedFile()
    {
        var handler = new RecordingHandler();
        var api = new CistaNasApiClient(new HttpClient(handler) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, "vol");

        var ws = new CistaNasFileSystem.WriteState("file.txt", existingFileId: "file.txt");
        ws.Write(new byte[] { 1, 2, 3 }, 0, 3, 0);

        fs.UploadWriteState(ws);

        // POST（アップロード）は1回以上呼ばれる
        Assert.Contains(handler.Requests, r => r.Method == "POST");
        // DELETE は呼ばれない（修正前は ExistingFileId==PlainName を DELETE して新ファイルを消していた）
        Assert.DoesNotContain(handler.Requests, r => r.Method == "DELETE");
    }

    /// <summary>
    /// E2EE チャンクアップロード途中で失敗した場合、作成中の fileId を削除（ロールバック）し、
    /// 旧ファイルは保持すること。修正前は孤児の新ファイルがサーバーに残っていた。
    /// </summary>
    [Fact]
    public void UploadWriteState_E2eeChunkFailure_RollsBackCreatedFile()
    {
        var handler = new FailUploadChunkHandler();
        var api = new CistaNasApiClient(new HttpClient(handler) { BaseAddress = new Uri("http://test/") });
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        var fs = new CistaNasFileSystem(api, masterKey, "vol");

        var ws = new CistaNasFileSystem.WriteState("plain.txt", existingFileId: "oldfile");
        ws.Write(RandomNumberGenerator.GetBytes(100), 0, 100, 0);

        // UploadChunk 失敗で例外（ロールバック後に再送）
        Assert.ThrowsAny<Exception>(() => fs.UploadWriteState(ws));

        // 作成中 fileId の DELETE（ロールバック）が呼ばれる
        Assert.Contains(handler.Requests,
            r => r.Method == "DELETE" && r.Uri.Contains(FailUploadChunkHandler.CreatedFileId));
        // 旧ファイル(oldfile)の DELETE は呼ばれない（新ファイル未完成のため保持）
        Assert.DoesNotContain(handler.Requests,
            r => r.Method == "DELETE" && r.Uri.Contains("oldfile"));
    }
}
