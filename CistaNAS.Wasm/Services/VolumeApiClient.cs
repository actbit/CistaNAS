using System.Net.Http.Json;
using CistaNAS.Wasm.Models;

namespace CistaNAS.Wasm.Services;

/// <summary>ボリューム API クライアント。</summary>
public sealed class VolumeApiClient
{
    private readonly HttpClient _http;

    public VolumeApiClient(HttpClient http) => _http = http;

    /// <summary>ユーザーがアクセス可能なボリューム一覧。</summary>
    public async Task<IReadOnlyList<VolumeInfo>> ListAsync()
    {
        var list = await _http.GetFromJsonAsync<List<VolumeInfo>>("/api/v1/volumes");
        return list ?? [];
    }

    /// <summary>ボリューム作成。</summary>
    public async Task<VolumeInfo> CreateAsync(string name, string username, string? password, bool encrypted)
    {
        var response = await _http.PostAsJsonAsync("/api/v1/volumes",
            new CreateVolumeRequest(name, username, password, encrypted));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<VolumeInfo>())!;
    }

    /// <summary>E2EE ボリューム作成。</summary>
    public async Task<VolumeInfo> CreateE2eeAsync(string name, string username, UserWrappedKey wrappedKey, int chunkSize = 1048576)
    {
        var response = await _http.PostAsJsonAsync("/api/v1/e2ee/create-volume",
            new E2eeCreateVolumeRequest(name, username, wrappedKey, chunkSize));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<VolumeInfo>())!;
    }

    /// <summary>ボリュームマウント。</summary>
    public async Task<VolumeInfo> MountAsync(string name, string username, string? password)
    {
        var response = await _http.PostAsJsonAsync($"/api/v1/volumes/{Uri.EscapeDataString(name)}/mount",
            new MountRequest(name, username, password));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<VolumeInfo>())!;
    }

    /// <summary>E2EE ボリュームマウント（アクセス権チェックのみ）。</summary>
    public async Task<VolumeInfo> MountE2eeAsync(string name, string username)
    {
        var response = await _http.PostAsJsonAsync($"/api/v1/e2ee/{Uri.EscapeDataString(name)}/mount",
            new { });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<VolumeInfo>())!;
    }

    /// <summary>ボリュームロック。</summary>
    public async Task LockAsync(string name)
    {
        var response = await _http.PostAsync($"/api/v1/volumes/{Uri.EscapeDataString(name)}/lock", null);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>ボリューム削除。</summary>
    public async Task DeleteAsync(string name)
    {
        var response = await _http.DeleteAsync($"/api/v1/volumes/{Uri.EscapeDataString(name)}");
        response.EnsureSuccessStatusCode();
    }

    /// <summary>アクセス権付与。</summary>
    public async Task GrantAccessAsync(string volumeName, string targetUsername, string targetPassword, string granterPassword)
    {
        var response = await _http.PostAsJsonAsync($"/api/v1/volumes/{Uri.EscapeDataString(volumeName)}/grant",
            new GrantAccessRequest(targetUsername, targetPassword, granterPassword));
        response.EnsureSuccessStatusCode();
    }

    /// <summary>アクセス権剥奪。</summary>
    public async Task RevokeAccessAsync(string volumeName, string targetUsername)
    {
        var response = await _http.PostAsJsonAsync($"/api/v1/volumes/{Uri.EscapeDataString(volumeName)}/revoke",
            new RevokeAccessRequest(targetUsername));
        response.EnsureSuccessStatusCode();
    }

    /// <summary>グループアクセス付与。</summary>
    public async Task GrantGroupAccessAsync(string volumeName, string groupName)
    {
        var response = await _http.PostAsJsonAsync($"/api/v1/volumes/{Uri.EscapeDataString(volumeName)}/grant-group",
            new { GroupName = groupName });
        response.EnsureSuccessStatusCode();
    }

    /// <summary>グループアクセス剥奪。</summary>
    public async Task RevokeGroupAccessAsync(string volumeName, string groupName)
    {
        var response = await _http.PostAsJsonAsync($"/api/v1/volumes/{Uri.EscapeDataString(volumeName)}/revoke-group",
            new { GroupName = groupName });
        response.EnsureSuccessStatusCode();
    }

    /// <summary>E2EE ラップ鍵を取得。</summary>
    public async Task<WrappedKeyResponse?> GetWrappedKeyAsync(string volumeName, string username)
    {
        var response = await _http.GetAsync(
            $"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/wrapped-key/{Uri.EscapeDataString(username)}");
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<WrappedKeyResponse>();
    }

    /// <summary>E2EE ラップ鍵を追加。</summary>
    public async Task AddE2eeWrappedKeyAsync(string volumeName, string targetUsername, UserWrappedKey wrappedKey)
    {
        var response = await _http.PostAsJsonAsync(
            $"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/add-wrapped-key",
            new E2eeAddWrappedKeyRequest(targetUsername, wrappedKey));
        response.EnsureSuccessStatusCode();
    }

    /// <summary>E2EE ラップ鍵を一括追加。</summary>
    public async Task AddE2eeWrappedKeysBatchAsync(string volumeName, Dictionary<string, UserWrappedKey> wrappedKeys)
    {
        var response = await _http.PostAsJsonAsync(
            $"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/add-wrapped-keys-batch",
            new AddE2eeWrappedKeysBatchRequest(wrappedKeys));
        response.EnsureSuccessStatusCode();
    }

    /// <summary>グループ E2EE ボリューム作成。</summary>
    public async Task<VolumeInfo> CreateGroupE2eeAsync(string groupName, UserWrappedKey ownerWrappedKey, int chunkSize = 1048576)
    {
        var response = await _http.PostAsJsonAsync("/api/v1/e2ee/create-group-volume",
            new CreateGroupE2eeVolumeRequest(groupName, ownerWrappedKey, chunkSize));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<VolumeInfo>())!;
    }

    /// <summary>グループメンバーの公開鍵一覧を取得。</summary>
    public async Task<IReadOnlyList<(string Username, string? PublicKey)>> GetGroupMembersWithPublicKeysAsync(string volumeName)
    {
        var response = await _http.GetAsync(
            $"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/group-members");
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadFromJsonAsync<List<MemberPublicKey>>();
        return json?.Select(m => (m.Username, m.PublicKey)).ToList() ?? [];
    }

    private sealed record MemberPublicKey(string Username, string? PublicKey);
}
