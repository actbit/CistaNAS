using System.Net.Http.Json;

namespace CistaNAS.Wasm.Services;

/// <summary>アカウント管理 API クライアント。</summary>
public sealed class AccountApiClient
{
    private readonly HttpClient _http;

    public AccountApiClient(HttpClient http) => _http = http;

    /// <summary>ユーザー一覧（admin）。</summary>
    public async Task<IReadOnlyList<UserWithRoles>> ListWithRolesAsync()
    {
        var response = await _http.GetAsync("/api/v1/account/users");
        if (!response.IsSuccessStatusCode) return [];
        return await response.Content.ReadFromJsonAsync<List<UserWithRoles>>() ?? [];
    }

    /// <summary>ユーザー作成（admin）。</summary>
    public async Task CreateUserAsync(string username, string password, string role = "user")
    {
        var response = await _http.PostAsJsonAsync("/api/v1/account/users", new
        {
            Username = username,
            Password = password,
            Role = role
        });
        response.EnsureSuccessStatusCode();
    }

    /// <summary>ユーザー削除（admin）。</summary>
    public async Task DeleteUserAsync(string username)
    {
        var response = await _http.DeleteAsync($"/api/v1/account/users/{Uri.EscapeDataString(username)}");
        response.EnsureSuccessStatusCode();
    }

    /// <summary>admin かどうか。</summary>
    public async Task<bool> IsAdminAsync(string username)
    {
        // WasmAuthStateProvider の JWT クレームから判定
        // 実際の API コールは不要
        return false; // 呼び出し元で AuthProvider を使う
    }

    /// <summary>公開鍵を取得。</summary>
    public async Task<string?> GetPublicKeyAsync(string username)
    {
        var response = await _http.GetAsync($"/api/v1/e2ee/public-key/{Uri.EscapeDataString(username)}");
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<PublicKeyResponse>();
        return result?.PublicKey;
    }

    /// <summary>自分の公開鍵を登録。</summary>
    public async Task UpdatePublicKeyAsync(string publicKey)
    {
        var response = await _http.PutAsync("/api/v1/e2ee/my-public-key",
            JsonContent.Create(new { PublicKey = publicKey }));
        response.EnsureSuccessStatusCode();
    }

    public sealed record UserWithRoles(string UserName, IList<string> Roles);
    private sealed record PublicKeyResponse(string PublicKey);
}
