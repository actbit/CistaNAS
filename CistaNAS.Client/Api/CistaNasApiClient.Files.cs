using System.Net.Http.Json;
using System.Text.Json;

namespace CistaNAS.Client.Api;

/// <summary>ファイル操作の拡張メソッド。</summary>
public static class CistaNasApiClientFiles
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>ボリューム内のファイル一覧を取得する。</summary>
    public static async Task<List<FileMetadata>> ListFilesAsync(this CistaNasApiClient client, string volumeName)
    {
        var http = GetHttp(client);
        var res = await http.GetAsync($"/api/v1/files/{Uri.EscapeDataString(volumeName)}/");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        var files = json.GetProperty("files");
        var result = new List<FileMetadata>();
        foreach (var f in files.EnumerateArray())
        {
            result.Add(new FileMetadata
            {
                Name = f.GetProperty("name").GetString()!,
                Length = f.GetProperty("length").GetInt64(),
                CreatedAt = f.GetProperty("createdAt").GetDateTimeOffset(),
                ModifiedAt = f.GetProperty("modifiedAt").GetDateTimeOffset(),
            });
        }
        return result;
    }

    /// <summary>ファイルをアップロードする。</summary>
    public static async Task<FileMetadata> UploadFileAsync(this CistaNasApiClient client, string volumeName, string filePath, byte[] data)
    {
        var http = GetHttp(client);
        var content = new ByteArrayContent(data);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        var res = await http.PostAsync($"/api/v1/files/{Uri.EscapeDataString(volumeName)}/{Uri.EscapeDataString(filePath)}", content);
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return new FileMetadata
        {
            Name = json.GetProperty("name").GetString()!,
            Length = json.GetProperty("length").GetInt64(),
            CreatedAt = json.GetProperty("createdAt").GetDateTimeOffset(),
            ModifiedAt = json.GetProperty("modifiedAt").GetDateTimeOffset(),
        };
    }

    /// <summary>ファイルをアップロードする（Stream 版）。</summary>
    public static async Task<FileMetadata> UploadFileAsync(this CistaNasApiClient client, string volumeName, string filePath, Stream dataStream)
    {
        var http = GetHttp(client);
        var content = new StreamContent(dataStream);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        var res = await http.PostAsync($"/api/v1/files/{Uri.EscapeDataString(volumeName)}/{Uri.EscapeDataString(filePath)}", content);
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return new FileMetadata
        {
            Name = json.GetProperty("name").GetString()!,
            Length = json.GetProperty("length").GetInt64(),
            CreatedAt = json.GetProperty("createdAt").GetDateTimeOffset(),
            ModifiedAt = json.GetProperty("modifiedAt").GetDateTimeOffset(),
        };
    }

    /// <summary>ファイルをダウンロードする。</summary>
    public static async Task<byte[]> DownloadFileAsync(this CistaNasApiClient client, string volumeName, string filePath)
    {
        var http = GetHttp(client);
        var res = await http.GetAsync($"/api/v1/files/{Uri.EscapeDataString(volumeName)}/{Uri.EscapeDataString(filePath)}");
        res.EnsureSuccessStatusCode();
        return await res.Content.ReadAsByteArrayAsync();
    }

    /// <summary>ファイルをダウンロードする（Stream 版）。</summary>
    public static async Task<Stream> DownloadFileStreamAsync(this CistaNasApiClient client, string volumeName, string filePath)
    {
        var http = GetHttp(client);
        var res = await http.GetAsync($"/api/v1/files/{Uri.EscapeDataString(volumeName)}/{Uri.EscapeDataString(filePath)}", System.Net.Http.HttpCompletionOption.ResponseHeadersRead);
        res.EnsureSuccessStatusCode();
        return await res.Content.ReadAsStreamAsync();
    }

    /// <summary>ファイルを削除する。</summary>
    public static async Task DeleteFileAsync(this CistaNasApiClient client, string volumeName, string filePath)
    {
        var http = GetHttp(client);
        var res = await http.DeleteAsync($"/api/v1/files/{Uri.EscapeDataString(volumeName)}/{Uri.EscapeDataString(filePath)}");
        res.EnsureSuccessStatusCode();
    }

    /// <summary>ファイルの一部をダウンロードする（Range リクエスト対応）。</summary>
    public static async Task<byte[]> DownloadFileRangeAsync(this CistaNasApiClient client, string volumeName, string filePath, long offset, int count)
    {
        var http = GetHttp(client);
        using var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get,
            $"/api/v1/files/{Uri.EscapeDataString(volumeName)}/{Uri.EscapeDataString(filePath)}");
        request.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(offset, offset + count - 1);
        var res = await http.SendAsync(request, System.Net.Http.HttpCompletionOption.ResponseContentRead);
        if (res.StatusCode == System.Net.HttpStatusCode.RequestedRangeNotSatisfiable)
            return Array.Empty<byte>();
        res.EnsureSuccessStatusCode();
        return await res.Content.ReadAsByteArrayAsync();
    }

    private static HttpClient GetHttp(CistaNasApiClient client)
    {
        var field = typeof(CistaNasApiClient).GetField("_http", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?? throw new InvalidOperationException("_http フィールドが見つかりません。");
        return (HttpClient?)field.GetValue(client) ?? throw new InvalidOperationException("_http が null です。");
    }
}

/// <summary>ファイルメタデータ。</summary>
public class FileMetadata
{
    public required string Name { get; set; }
    public long Length { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }
}
