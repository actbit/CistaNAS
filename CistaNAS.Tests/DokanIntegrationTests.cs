using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CistaNAS.Client;
using CistaNAS.Client.Api;
using DokanNet;
using FileAccess = System.IO.FileAccess;
using Xunit;

namespace CistaNAS.Tests;

/// <summary>
/// Dokan 実機統合テスト（dokan2 ドライバ必須）。HttpMessageHandler モックでサーバーを模擬し、
/// 実ドライバ経由でファイル操作を行って「部分編集→末尾保持」「差分保存」を自動検証する。
/// CI（dokan2 無し）では Category=RequiresDokan を除外すること。
/// </summary>
[Trait("Category", "RequiresDokan")]
public class DokanIntegrationTests
{
    /// <summary>非E2EE サーバーをインメモリで模擬（POST 全体 / GET Range / PATCH 部分書き込み / DELETE / ListFiles）。</summary>
    private sealed class InMemoryStorageHandler : HttpMessageHandler
    {
        public readonly Dictionary<string, byte[]> Files = new(StringComparer.OrdinalIgnoreCase);
        public int PatchCount;
        public int PostCount;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var uri = request.RequestUri!.ToString();
            var method = request.Method.Method;

            const string prefix = "/api/v1/files/vol/";
            int idx = uri.IndexOf(prefix, StringComparison.Ordinal);
            if (idx < 0) return NotFound();

            string rest = uri[(idx + prefix.Length)..];
            string pathPart = rest.Split('?')[0];
            string path = Uri.UnescapeDataString(pathPart);

            // ListFiles（path 空）
            if (method == "GET" && string.IsNullOrEmpty(path))
            {
                var filesJson = string.Join(",", Files.Select(f => FileMetaJson(f.Key, f.Value.Length)));
                return Ok($"{{\"files\":[{filesJson}]}}");
            }

            if (method == "POST")
            {
                PostCount++;
                byte[] data = request.Content!.ReadAsByteArrayAsync(ct).GetAwaiter().GetResult();
                Files[path] = data;
                return Ok(FileMetaJson(path, data.Length));
            }

            if (method == "GET")
            {
                if (!Files.TryGetValue(path, out var data)) return NotFound();
                var range = request.Headers.Range;
                byte[] result;
                if (range is not null && range.Ranges.Count > 0)
                {
                    var r = range.Ranges.First();
                    long start = r.From ?? 0;
                    long end = r.To ?? (data.Length - 1);
                    end = Math.Min(end, data.Length - 1);
                    if (start > end || start >= data.Length)
                        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.RequestedRangeNotSatisfiable));
                    int len = (int)(end - start + 1);
                    result = new byte[len];
                    Array.Copy(data, (int)start, result, 0, len);
                }
                else
                {
                    result = data;
                }
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(result) });
            }

            if (method == "PATCH")
            {
                PatchCount++;
                byte[] data = request.Content!.ReadAsByteArrayAsync(ct).GetAwaiter().GetResult();
                long offset = ParseOffset(uri);
                Files.TryGetValue(path, out var existing);
                existing ??= Array.Empty<byte>();
                long newLen = Math.Max(existing.Length, offset + data.Length);
                byte[] updated = new byte[newLen];
                Array.Copy(existing, updated, existing.Length);
                Array.Copy(data, 0, updated, (int)offset, data.Length);
                Files[path] = updated;
                return Ok(FileMetaJson(path, newLen));
            }

            if (method == "DELETE")
            {
                Files.Remove(path);
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
            }

            return NotFound();
        }

        private static long ParseOffset(string uri)
        {
            int q = uri.IndexOf('?');
            if (q < 0) return 0;
            foreach (var kv in uri[(q + 1)..].Split('&'))
            {
                var p = kv.Split('=');
                if (p.Length == 2 && p[0] == "offset" && long.TryParse(p[1], out var o)) return o;
            }
            return 0;
        }

        private static string FileMetaJson(string name, long length)
            => $"{{\"name\":\"{name}\",\"length\":{length},\"createdAt\":\"2026-01-01T00:00:00Z\",\"modifiedAt\":\"2026-01-01T00:00:00Z\"}}";

        private static Task<HttpResponseMessage> Ok(string json)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent(json, Encoding.UTF8, "application/json") });

        private static Task<HttpResponseMessage> NotFound()
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }

    private static char FindFreeDrive()
    {
        for (char c = 'Z'; c >= 'D'; c--)
        {
            if (!Directory.Exists($"{c}:\\"))
                return c;
        }
        throw new InvalidOperationException("空きドライブ文字がありません");
    }

    private static async Task WaitForMountAsync(string mountPoint)
    {
        for (int i = 0; i < 100; i++)
        {
            try { Directory.GetFiles(mountPoint); return; }
            catch { await Task.Delay(100); }
        }
        throw new TimeoutException($"Dokan マウントがタイムアウト: {mountPoint}");
    }

    private static (DokanNet.Dokan dokan, DokanInstance instance, Task loop) Mount(CistaNasFileSystem fs, string mountPoint)
    {
        var dokan = new DokanNet.Dokan(logger: null!);
        var builder = new DokanInstanceBuilder(dokan)
            .ConfigureOptions(options =>
            {
                options.MountPoint = mountPoint;
                options.Options = DokanOptions.FixedDrive;
                options.Version = DokanInstanceBuilder.DOKAN_VERSION;
            });
        var instance = builder.Build(fs);
        var loop = Task.Run(() => instance.WaitForFileSystemClosed(uint.MaxValue));
        return (dokan, instance, loop);
    }

    /// <summary>非E2EE: 既存ファイルの先頭1バイトを編集し、末尾（999バイト）が保持されることを検証。</summary>
    [Fact]
    public async Task NonE2ee_PartialEdit_PreservesTail()
    {
        var storage = new InMemoryStorageHandler();
        var api = new CistaNasApiClient(new HttpClient(storage) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, "vol");

        char drive = FindFreeDrive();
        string mountPoint = $"{drive}:\\";
        var (dokan, instance, loop) = Mount(fs, mountPoint);
        await WaitForMountAsync(mountPoint);

        try
        {
            // 初期ファイル作成（全体書き込み）
            byte[] initial = Enumerable.Range(0, 1000).Select(i => (byte)(i & 0xFF)).ToArray();
            File.WriteAllBytes(mountPoint + "test.txt", initial);

            // 部分編集: 先頭1バイトを 0xFF に（末尾は触らない）
            using (var f = new FileStream(mountPoint + "test.txt", FileMode.Open, FileAccess.Write))
            {
                f.Seek(0, SeekOrigin.Begin);
                f.Write(new byte[] { 0xFF }, 0, 1);
            }

            // 検証: 末尾保持
            byte[] result = File.ReadAllBytes(mountPoint + "test.txt");
            Assert.Equal(1000, result.Length);
            Assert.Equal((byte)0xFF, result[0]);
            for (int i = 1; i < 1000; i++)
                Assert.Equal(initial[i], result[i]);

            // 差分保存の検証: 部分編集は PATCH（全体 POST ではない）
            Assert.True(storage.PatchCount > 0, "差分保存で PATCH が呼ばれるべき");
        }
        finally
        {
            dokan.RemoveMountPoint(mountPoint);
            await loop;
            instance.Dispose();
        }
    }

    /// <summary>非E2EE: 書き込み中のハンドルから読み込むと、書き込んだ内容が見えることを検証（ReadFile WriteState 対応）。</summary>
    [Fact]
    public async Task NonE2ee_ReadDuringWrite_ReflectsBuffer()
    {
        var storage = new InMemoryStorageHandler();
        // 事前に既存ファイルを用意
        storage.Files["edit.txt"] = Enumerable.Range(0, 500).Select(i => (byte)'A').ToArray();

        var api = new CistaNasApiClient(new HttpClient(storage) { BaseAddress = new Uri("http://test/") });
        var fs = new CistaNasFileSystem(api, "vol");

        char drive = FindFreeDrive();
        string mountPoint = $"{drive}:\\";
        var (dokan, instance, loop) = Mount(fs, mountPoint);
        await WaitForMountAsync(mountPoint);

        try
        {
            using var f = new FileStream(mountPoint + "edit.txt", FileMode.Open, FileAccess.ReadWrite);
            f.Write(new byte[] { (byte)'Z' }, 0, 1);  // 先頭を Z に（まだ保存前）
            f.Flush();

            // 同じハンドル（WriteState）で読む → 書いた内容（Z）と未編集末尾（A...）が見える
            f.Seek(0, SeekOrigin.Begin);
            byte[] buf = new byte[10];
            int read = f.Read(buf, 0, 10);
            Assert.Equal(10, read);
            Assert.Equal((byte)'Z', buf[0]);
            Assert.Equal((byte)'A', buf[1]);
        }
        finally
        {
            dokan.RemoveMountPoint(mountPoint);
            await loop;
            instance.Dispose();
        }
    }

    /// <summary>E2EE サーバーをインメモリで模擬（チャンクは opaque、ChunkRevisions を管理）。</summary>
    private sealed class E2eeStorageHandler : HttpMessageHandler
    {
        private sealed class FileEntry
        {
            public string FileId = "";
            public string EncryptedName = "";
            public long EncryptedLength;
            public int ChunkCount;
            public Dictionary<int, byte[]> Chunks = new();
            public Dictionary<int, int> Revisions = new();
        }

        private readonly Dictionary<string, FileEntry> _byFileId = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var uri = request.RequestUri!.ToString();
            var method = request.Method.Method;

            const string prefix = "/api/v1/e2ee/vol/";
            int idx = uri.IndexOf(prefix, StringComparison.Ordinal);
            if (idx < 0) return new HttpResponseMessage(HttpStatusCode.NotFound);

            string rest = uri[(idx + prefix.Length)..];
            string pathPart = rest.Split('?')[0];
            var seg = pathPart.Split('/', StringSplitOptions.RemoveEmptyEntries);
            string query = rest.Contains('?') ? rest[(rest.IndexOf('?') + 1)..] : "";

            if (method == "POST" && seg.Length > 0 && seg[0] == "create-file")
            {
                var body = await request.Content!.ReadFromJsonAsync<JsonElement>(ct);
                string fileId = Guid.NewGuid().ToString("N");
                _byFileId[fileId] = new FileEntry
                {
                    FileId = fileId,
                    EncryptedName = body.GetProperty("encryptedName").GetString()!,
                    EncryptedLength = body.GetProperty("encryptedLength").GetInt64(),
                    ChunkCount = body.GetProperty("chunkCount").GetInt32(),
                };
                return OkJson($"{{\"fileId\":\"{fileId}\"}}");
            }

            if (method == "POST" && seg.Length > 2 && seg[0] == "upload-chunk")
            {
                string fileId = seg[1];
                int chunkIndex = int.Parse(seg[2]);
                bool replace = query.Split('&').Contains("replace=true");
                var entry = _byFileId[fileId];
                byte[] data = await request.Content!.ReadAsByteArrayAsync(ct);
                bool isExisting = entry.Chunks.ContainsKey(chunkIndex);
                entry.Chunks[chunkIndex] = data;
                entry.Revisions[chunkIndex] = (replace && isExisting)
                    ? entry.Revisions.GetValueOrDefault(chunkIndex, 0) + 1
                    : 0;
                return OkJson("");
            }

            if (method == "PATCH" && seg.Length > 1 && seg[0] == "finalize-file")
            {
                string fileId = seg[1];
                var body = await request.Content!.ReadFromJsonAsync<JsonElement>(ct);
                if (_byFileId.TryGetValue(fileId, out var e))
                    e.EncryptedLength = body.GetProperty("actualEncryptedLength").GetInt64();
                return OkJson("");
            }

            if (method == "GET" && seg.Length > 2 && seg[0] == "download-chunk")
            {
                string fileId = seg[1];
                int chunkIndex = int.Parse(seg[2]);
                var entry = _byFileId[fileId];
                if (!entry.Chunks.TryGetValue(chunkIndex, out var data))
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
                int revision = entry.Revisions.GetValueOrDefault(chunkIndex, 0);
                var res = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(data) };
                res.Headers.Add("X-Chunk-Revision", revision.ToString());
                return res;
            }

            if (method == "GET" && seg.Length > 2 && seg[0] == "chunk-hash")
            {
                string fileId = seg[1];
                int chunkIndex = int.Parse(seg[2]);
                var entry = _byFileId[fileId];
                if (!entry.Chunks.TryGetValue(chunkIndex, out var data))
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
                string hash = Convert.ToHexString(SHA256.HashData(data));
                int revision = entry.Revisions.GetValueOrDefault(chunkIndex, 0);
                return OkJson($"{{\"hash\":\"{hash}\",\"revision\":{revision}}}");
            }

            if (method == "GET" && seg.Length == 1 && seg[0] == "files")
            {
                var filesJson = string.Join(",", _byFileId.Values.Select(e =>
                    $"{{\"fileId\":\"{e.FileId}\",\"encryptedName\":\"{e.EncryptedName}\",\"encryptedLength\":{e.EncryptedLength},\"chunkCount\":{e.ChunkCount},\"createdAt\":\"2026-01-01T00:00:00Z\",\"modifiedAt\":\"2026-01-01T00:00:00Z\"}}"));
                return OkJson($"{{\"files\":[{filesJson}]}}");
            }

            if (method == "DELETE" && seg.Length > 1 && seg[0] == "files")
            {
                _byFileId.Remove(seg[1]);
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        private static HttpResponseMessage OkJson(string json)
            => new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    }

    /// <summary>E2EE: 既存ファイルの先頭1バイトを編集し、末尾が保持されることを検証（revision 差分上書き）。</summary>
    [Fact]
    public async Task E2ee_PartialEdit_PreservesTail()
    {
        var storage = new E2eeStorageHandler();
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        var api = new CistaNasApiClient(new HttpClient(storage) { BaseAddress = new Uri("http://test/") });
        int chunkSize = 4096;  // 小さいチャンクサイズで高速テスト
        var fs = new CistaNasFileSystem(api, masterKey, "vol", chunkSize: chunkSize);

        char drive = FindFreeDrive();
        string mountPoint = $"{drive}:\\";
        var (dokan, instance, loop) = Mount(fs, mountPoint);
        await WaitForMountAsync(mountPoint);

        try
        {
            // 初期ファイル作成（2チャンク + 端数）
            byte[] initial = new byte[chunkSize * 2 + 1000];
            for (int i = 0; i < initial.Length; i++) initial[i] = (byte)(i & 0xFF);
            File.WriteAllBytes(mountPoint + "secret.txt", initial);

            // 部分編集: 先頭1バイトを 0xFF に
            using (var f = new FileStream(mountPoint + "secret.txt", FileMode.Open, FileAccess.Write))
            {
                f.Seek(0, SeekOrigin.Begin);
                f.Write(new byte[] { 0xFF }, 0, 1);
            }

            // 検証: 末尾保持（revision 差分上書きで chunk0 だけ更新、chunk1/2 は維持）
            byte[] result = File.ReadAllBytes(mountPoint + "secret.txt");
            Assert.Equal(initial.Length, result.Length);
            Assert.Equal((byte)0xFF, result[0]);
            for (int i = 1; i < initial.Length; i++)
                Assert.Equal(initial[i], result[i]);
        }
        finally
        {
            dokan.RemoveMountPoint(mountPoint);
            await loop;
            instance.Dispose();
        }
    }
}
