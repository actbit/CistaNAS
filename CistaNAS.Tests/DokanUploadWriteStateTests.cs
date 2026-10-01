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
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShrinkDuringSave_PreservesLaterWritesButCannotRestoreEarlierTruncatedWrites(bool fail)
    {
        using var storage = new StatefulPlainFileHandler(Enumerable.Repeat((byte)9, 100).ToArray());
        using var paused = new PauseSaveHandler(storage, fail);
        using var http = new HttpClient(paused) { BaseAddress = new Uri("http://test/") };
        using var fs = new CistaNasFileSystem(new CistaNasApiClient(http), "vol");
        var state = new CistaNasFileSystem.PlainRangeWriteState(fs, "file.txt", "file.txt", 100);
        Task save = Task.CompletedTask;
        try
        {
            state.Write([2, 2, 2], 0, 3, 80);
            save = Task.Run(() => fs.UploadWriteState(state));
            await paused.Reached.Task.WaitAsync(TimeSpan.FromSeconds(5));
            state.Gate.Wait();
            try
            {
                state.SetDeclaredSize(50);
                state.SetDeclaredSize(100);
                state.Write([7], 0, 1, 70);
            }
            finally { state.Gate.Release(); }
            paused.Release.TrySetResult();
            if (fail) await Assert.ThrowsAsync<HttpRequestException>(() => save);
            else await save.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(state.HasPending);
            fs.UploadWriteState(state);
            byte[] expected = new byte[100];
            Array.Fill(expected, (byte)9, 0, 50);
            expected[70] = 7;
            Assert.Equal(expected, storage.Content);
        }
        finally
        {
            paused.Release.TrySetResult();
            try { await save.WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
            state.Dispose();
        }
    }

    private sealed class PauseSaveHandler(HttpMessageHandler inner, bool fail) : HttpMessageHandler
    {
        private readonly HttpMessageInvoker _inner = new(inner, disposeHandler: false);
        private bool _paused;
        public TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var response = await _inner.SendAsync(request, ct);
            if (!_paused && request.Method == HttpMethod.Patch)
            {
                _paused = true;
                Reached.TrySetResult();
                await Release.Task.WaitAsync(ct);
                if (fail) { response.Dispose(); return new HttpResponseMessage(HttpStatusCode.InternalServerError); }
            }
            return response;
        }
        protected override void Dispose(bool disposing) { if (disposing) _inner.Dispose(); base.Dispose(disposing); }
    }

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
                int offset = int.Parse(request.RequestUri!.Query.Replace("?offset=", ""));
                byte[] data = request.Content!.ReadAsByteArrayAsync(cancellationToken).GetAwaiter().GetResult();
                byte[] updated = new byte[Math.Max(Content.Length, offset + data.Length)];
                Content.CopyTo(updated, 0);
                data.CopyTo(updated, offset);
                Content = updated;
                PatchCount++;
                return Metadata();
            }
            if (request.Method == HttpMethod.Get)
            {
                if (request.Headers.Range is { } range)
                {
                    var part = range.Ranges.Single();
                    int start = (int)part.From!.Value;
                    int end = (int)Math.Min(part.To!.Value, Content.Length - 1);
                    var response = new HttpResponseMessage(HttpStatusCode.PartialContent)
                    { Content = new ByteArrayContent(Content[start..(end + 1)]) };
                    response.Content.Headers.ContentRange = new System.Net.Http.Headers.ContentRangeHeaderValue(start, end, Content.Length);
                    return Task.FromResult(response);
                }
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Content) });
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private Task<HttpResponseMessage> Metadata() => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                $"{{\"name\":\"file.txt\",\"length\":{Content.Length},\"createdAt\":\"2026-01-01T00:00:00Z\",\"modifiedAt\":\"2026-01-01T00:00:00Z\"}}",
                Encoding.UTF8, "application/json"),
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PlainSecondSave_PreservesEarlierSavedBytes(bool truncateAtOpen)
    {
        using var handler = new StatefulPlainFileHandler(truncateAtOpen ? new byte[100] : []);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://test/") };
        using var fs = new CistaNasFileSystem(new CistaNasApiClient(http), "vol");
        var state = new CistaNasFileSystem.PlainRangeWriteState(fs, "file.txt", truncateAtOpen ? "file.txt" : null,
            truncateAtOpen ? 100 : 0) { TruncatedAtOpen = truncateAtOpen };
        try
        {
            if (truncateAtOpen) state.SetDeclaredSize(0);
            state.Write([1, 2, 3], 0, 3, 0);
            fs.UploadWriteState(state);
            state.Write([4, 5, 6], 0, 3, 3);
            fs.UploadWriteState(state);
            Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6 }, handler.Content);
        }
        finally { state.Dispose(); }
    }

    [Fact]
    public void PlainNewFile_DeclaredTrailingZeroExtentIsPersisted()
    {
        using var handler = new StatefulPlainFileHandler([]);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://test/") };
        using var fs = new CistaNasFileSystem(new CistaNasApiClient(http), "vol");
        var state = new CistaNasFileSystem.PlainRangeWriteState(fs, "file.txt", null);
        try
        {
            state.SetDeclaredSize(6);
            state.Write([1, 2, 3], 0, 3, 0);
            fs.UploadWriteState(state);
            Assert.Equal(new byte[] { 1, 2, 3, 0, 0, 0 }, handler.Content);
        }
        finally { state.Dispose(); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PlainShrinkThenGrow_DoesNotRestoreTruncatedServerOrDirtyBytes(bool dirty)
    {
        using var handler = new StatefulPlainFileHandler(Enumerable.Repeat((byte)9, 100).ToArray());
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://test/") };
        using var fs = new CistaNasFileSystem(new CistaNasApiClient(http), "vol");
        var state = new CistaNasFileSystem.PlainRangeWriteState(fs, "file.txt", "file.txt", 100);
        try
        {
            if (dirty) state.Write([7, 7, 7], 0, 3, 80);
            state.SetDeclaredSize(50);
            state.SetDeclaredSize(100);
            fs.UploadWriteState(state);
            Assert.Equal(Enumerable.Repeat((byte)9, 50).Concat(new byte[50]), handler.Content);
        }
        finally { state.Dispose(); }
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
