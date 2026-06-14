using System.Net.Http.Json;
using System.Text.Json;

namespace CistaNAS.Client.Api;

/// <summary>E2EE 追加機能の拡張メソッド。</summary>
public static class CistaNasApiClientE2eeExtensions
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>E2EE ボリュームにユーザーの ECDH ラップキーを追加する。</summary>
    public static async Task AddWrappedKeyAsync(this CistaNasApiClient client, string volumeName, string username,
        byte[] wrappedNonce, byte[] wrappedCt, byte[] wrappedTag, byte[] ephemeralPublicKey)
    {
        var http = GetHttp(client);
        var req = new
        {
            username,
            wrappedMasterKey = new
            {
                wrapType = "ecdh",
                kdf = new
                {
                    algorithm = "pbkdf2-sha256",
                    iterations = 0,
                    salt = Array.Empty<byte>()
                },
                ephemeralPublicKey,
                wrappedMasterKey = new
                {
                    algorithm = "aes-256-gcm",
                    nonce = wrappedNonce,
                    ciphertext = wrappedCt,
                    tag = wrappedTag
                }
            }
        };
        var res = await http.PostAsJsonAsync($"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/add-wrapped-key", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>グループメンバーの公開鍵一覧を取得する（ECDH 共有用）。</summary>
    public static async Task<List<GroupMemberInfo>> GetGroupMembersAsync(this CistaNasApiClient client, string volumeName)
    {
        var http = GetHttp(client);
        var res = await http.GetAsync($"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/group-members");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        var result = new List<GroupMemberInfo>();
        foreach (var m in json.EnumerateArray())
        {
            result.Add(new GroupMemberInfo
            {
                Username = m.GetProperty("username").GetString()!,
                PublicKey = m.TryGetProperty("publicKey", out var pk) ? pk.GetString() : null,
            });
        }
        return result;
    }

    /// <summary>E2EE ボリュームに複数ユーザーの ECDH ラップキーを一括追加する。</summary>
    public static async Task AddWrappedKeysBatchAsync(this CistaNasApiClient client, string volumeName,
        Dictionary<string, (byte[] nonce, byte[] ct, byte[] tag, byte[] ephemeralPublicKey)> wrappedKeys)
    {
        var http = GetHttp(client);
        var keys = new Dictionary<string, object>();
        foreach (var (username, (nonce, ct, tag, ephemeralPublicKey)) in wrappedKeys)
        {
            keys[username] = new
            {
                wrapType = "ecdh",
                kdf = new
                {
                    algorithm = "pbkdf2-sha256",
                    iterations = 0,
                    salt = Array.Empty<byte>()
                },
                ephemeralPublicKey,
                wrappedMasterKey = new
                {
                    algorithm = "aes-256-gcm",
                    nonce = nonce,
                    ciphertext = ct,
                    tag = tag
                }
            };
        }
        var req = new { wrappedKeys = keys };
        var res = await http.PostAsJsonAsync($"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/add-wrapped-keys-batch", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>ユーザーのクオータを設定する。</summary>
    public static async Task SetUserQuotaAsync(this CistaNasApiClient client, string volumeName, string username, long maxBytes)
    {
        var http = GetHttp(client);
        var req = new { maxBytes };
        var res = await http.PutAsJsonAsync($"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/quota/{Uri.EscapeDataString(username)}", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>ユーザーの公開鍵を取得する。</summary>
    public static async Task<string?> GetPublicKeyAsync(this CistaNasApiClient client, string username)
    {
        var http = GetHttp(client);
        var res = await http.GetAsync($"/api/v1/e2ee/public-key/{Uri.EscapeDataString(username)}");
        if (!res.IsSuccessStatusCode) return null;
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return json.TryGetProperty("publicKey", out var pk) ? pk.GetString() : null;
    }

    /// <summary>自分の公開鍵を設定する。</summary>
    public static async Task SetMyPublicKeyAsync(this CistaNasApiClient client, byte[] publicKey)
    {
        var http = GetHttp(client);
        var req = new { publicKey = Convert.ToBase64String(publicKey) };
        var res = await http.PutAsJsonAsync("/api/v1/e2ee/my-public-key", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>グループ専用 E2EE ボリュームを作成する（オーナー鍵は password ラップ）。</summary>
    public static async Task<VolumeInfo> CreateGroupVolumeAsync(this CistaNasApiClient client, string groupName,
        byte[] wrappedNonce, byte[] wrappedCt, byte[] wrappedTag, byte[] kdfSalt, int kdfIterations, int chunkSize = 1048576)
    {
        var http = GetHttp(client);
        var req = new
        {
            groupName,
            ownerWrappedKey = new
            {
                wrapType = "password",
                kdf = new
                {
                    algorithm = "pbkdf2-sha256",
                    iterations = kdfIterations,
                    salt = kdfSalt
                },
                wrappedMasterKey = new
                {
                    algorithm = "aes-256-gcm",
                    nonce = wrappedNonce,
                    ciphertext = wrappedCt,
                    tag = wrappedTag
                }
            },
            chunkSize
        };
        var res = await http.PostAsJsonAsync("/api/v1/e2ee/create-group-volume", req, JsonOpts);
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return new VolumeInfo
        {
            Name = json.GetProperty("name").GetString()!,
            Encrypted = json.TryGetProperty("encrypted", out var enc) && enc.GetBoolean(),
            EncryptionMode = json.TryGetProperty("encryptionMode", out var mode) ? mode.GetString() ?? "server" : "server",
            IsMounted = json.TryGetProperty("isMounted", out var mnt) && mnt.GetBoolean(),
            OwnerUser = json.TryGetProperty("ownerUser", out var owner) ? owner.GetString() ?? "" : "",
        };
    }

    private static HttpClient GetHttp(CistaNasApiClient client)
    {
        var field = typeof(CistaNasApiClient).GetField("_http", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?? throw new InvalidOperationException("_http フィールドが見つかりません。");
        return (HttpClient?)field.GetValue(client) ?? throw new InvalidOperationException("_http が null です。");
    }
}

/// <summary>グループメンバー情報。</summary>
public class GroupMemberInfo
{
    public required string Username { get; set; }
    public string? PublicKey { get; set; }
}
