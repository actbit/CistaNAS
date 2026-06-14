using System.Net.Http.Json;
using CistaNAS.Wasm.Models;

namespace CistaNAS.Wasm.Services;

/// <summary>
/// 認証 API クライアント。ログイン・パスワード変更等。
/// </summary>
public sealed class AuthApiClient
{
    private readonly HttpClient _http;

    public AuthApiClient(HttpClient http)
    {
        _http = http;
    }

    /// <summary>ログイン。成功時は JWT レスポンス、失敗時は null。</summary>
    public async Task<LoginResponse?> LoginAsync(string username, string password)
    {
        var response = await _http.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(username, password));
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized) return null;
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<LoginResponse>();
    }

    /// <summary>初期セットアップ。管理者アカウント作成。</summary>
    public async Task<bool> SetupAsync(string username, string password)
    {
        var response = await _http.PostAsJsonAsync("/api/v1/auth/setup", new SetupRequest(username, password));
        if (response.StatusCode == System.Net.HttpStatusCode.Conflict) return false;
        response.EnsureSuccessStatusCode();
        return true;
    }

    /// <summary>パスワード変更。</summary>
    public async Task<bool> ChangePasswordAsync(string oldPassword, string newPassword)
    {
        var response = await _http.PostAsJsonAsync("/api/v1/auth/change-password",
            new ChangePasswordRequest(oldPassword, newPassword));
        return response.IsSuccessStatusCode;
    }

    /// <summary>初期セットアップ済みか（ユーザーが存在するか）。</summary>
    public async Task<bool> HasAnyUsersAsync()
    {
        try
        {
            var response = await _http.GetAsync("/api/v1/auth/has-users");
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<HasUsersResponse>();
            return result?.HasUsers ?? true;
        }
        catch
        {
            return true; // エラー時はセットアップ済みとみなす
        }
    }

    private sealed record HasUsersResponse(bool HasUsers);
}
