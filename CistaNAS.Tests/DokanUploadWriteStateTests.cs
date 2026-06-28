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
}
