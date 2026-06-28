using System.Net;
using System.Net.Http;
using CistaNAS.Client;
using CistaNAS.Client.Api;

namespace CistaNAS.Tests;

/// <summary>
/// CistaNasFileSystem.UploadWriteState のテスト（Dokan ドライバ不要・HttpMessageHandler モック）。
/// Critical-3: 非E2EE 上書きで新ファイル削除を検証。
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
}
