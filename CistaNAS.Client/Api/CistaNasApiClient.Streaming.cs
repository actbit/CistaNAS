using System.Net.Http.Json;
using System.Text.Json;

namespace CistaNAS.Client.Api;

/// <summary>メディアストリーミングの拡張メソッド。</summary>
public static class CistaNasApiClientStreaming
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>ストリーミングトークンを発行する。</summary>
    public static async Task<string> IssueStreamTokenAsync(this CistaNasApiClient client, string volumeName, string fileName)
    {
        var http = GetHttp(client);
        var req = new { volumeName, fileName };
        var res = await http.PostAsJsonAsync("/api/v1/stream/token", req, JsonOpts);
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("token").GetString()!;
    }

    /// <summary>ストリーミングエンドポイントからファイルをダウンロードする。</summary>
    public static async Task<byte[]> StreamFileAsync(this CistaNasApiClient client, string volumeName, string filePath, string token)
    {
        var http = GetHttp(client);
        var res = await http.GetAsync($"/api/v1/stream/{Uri.EscapeDataString(volumeName)}/{Uri.EscapeDataString(filePath)}?token={Uri.EscapeDataString(token)}");
        res.EnsureSuccessStatusCode();
        return await res.Content.ReadAsByteArrayAsync();
    }

    /// <summary>ストリーミングエンドポイントからファイルをダウンロードする（Stream 版）。</summary>
    public static async Task<Stream> StreamFileStreamAsync(this CistaNasApiClient client, string volumeName, string filePath, string token)
    {
        var http = GetHttp(client);
        var res = await http.GetAsync($"/api/v1/stream/{Uri.EscapeDataString(volumeName)}/{Uri.EscapeDataString(filePath)}?token={Uri.EscapeDataString(token)}", System.Net.Http.HttpCompletionOption.ResponseHeadersRead);
        res.EnsureSuccessStatusCode();
        return await res.Content.ReadAsStreamAsync();
    }

    private static HttpClient GetHttp(CistaNasApiClient client)
    {
        var field = typeof(CistaNasApiClient).GetField("_http", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?? throw new InvalidOperationException("_http フィールドが見つかりません。");
        return (HttpClient?)field.GetValue(client) ?? throw new InvalidOperationException("_http が null です。");
    }
}
