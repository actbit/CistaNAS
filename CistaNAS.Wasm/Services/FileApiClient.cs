using System.Net.Http.Json;
using CistaNAS.Wasm.Models;

namespace CistaNAS.Wasm.Services;

/// <summary>ファイル API クライアント（通常ボリューム用）。</summary>
public sealed class FileApiClient
{
    private readonly HttpClient _http;

    public FileApiClient(HttpClient http) => _http = http;

    /// <summary>ファイル一覧。</summary>
    public async Task<ListFilesResponse> ListAsync(string volumeName)
    {
        var result = await _http.GetFromJsonAsync<ListFilesResponse>(
            $"/api/v1/files/{Uri.EscapeDataString(volumeName)}");
        return result ?? new ListFilesResponse([]);
    }

    /// <summary>ファイルアップロード。</summary>
    public async Task<FileMetadata> UploadAsync(string volumeName, string fileName, Stream content, long contentLength)
    {
        using var streamContent = new StreamContent(content);
        streamContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

        var response = await _http.PostAsync(
            $"/api/v1/files/{Uri.EscapeDataString(volumeName)}/{Uri.EscapeDataString(fileName)}", streamContent);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<FileMetadata>())!;
    }

    /// <summary>ファイルダウンロード URL を取得。</summary>
    public string GetDownloadUrl(string volumeName, string fileName, string token)
    {
        return $"{_http.BaseAddress}api/v1/stream/{Uri.EscapeDataString(volumeName)}/{Uri.EscapeDataString(fileName)}?token={token}";
    }

    /// <summary>ファイル削除。</summary>
    public async Task DeleteAsync(string volumeName, string fileName)
    {
        var response = await _http.DeleteAsync(
            $"/api/v1/files/{Uri.EscapeDataString(volumeName)}/{Uri.EscapeDataString(fileName)}");
        response.EnsureSuccessStatusCode();
    }

    /// <summary>ストリーミングトークン発行。</summary>
    public async Task<string> IssueStreamTokenAsync(string volumeName, string fileName)
    {
        var response = await _http.PostAsJsonAsync("/api/v1/stream/token",
            new StreamTokenRequest(volumeName, fileName));
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<TokenResponse>();
        return result?.Token ?? "";
    }

    private sealed record TokenResponse(string Token);
}
