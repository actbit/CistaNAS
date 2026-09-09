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
        var http = client._http;
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
        var http = client._http;
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
        var http = client._http;
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
        var http = client._http;
        var req = new { maxBytes };
        var res = await http.PutAsJsonAsync($"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/quota/{Uri.EscapeDataString(username)}", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>ユーザーの公開鍵を取得する。</summary>
    public static async Task<string?> GetPublicKeyAsync(this CistaNasApiClient client, string username)
    {
        var http = client._http;
        var res = await http.GetAsync($"/api/v1/e2ee/public-key/{Uri.EscapeDataString(username)}");
        if (!res.IsSuccessStatusCode) return null;
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return json.TryGetProperty("publicKey", out var pk) ? pk.GetString() : null;
    }

    /// <summary>自分の公開鍵を設定する。</summary>
    public static async Task SetMyPublicKeyAsync(this CistaNasApiClient client, byte[] publicKey)
    {
        var http = client._http;
        var req = new { publicKey = Convert.ToBase64String(publicKey) };
        var res = await http.PutAsJsonAsync("/api/v1/e2ee/my-public-key", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>グループ専用 E2EE ボリュームを作成する（オーナー鍵は password ラップ。レガシー PBKDF2）。</summary>
    public static Task<VolumeInfo> CreateGroupVolumeAsync(this CistaNasApiClient client, string groupName,
        byte[] wrappedNonce, byte[] wrappedCt, byte[] wrappedTag, byte[] kdfSalt, int kdfIterations, int chunkSize = 1048576)
        => CreateGroupVolumeAsync(client, groupName, wrappedNonce, wrappedCt, wrappedTag, kdfSalt,
            KdfInfo.LegacyPbkdf2(kdfIterations), chunkSize);

    /// <summary>グループ専用 E2EE ボリュームを作成する（オーナー鍵は password ラップ。KDF スペック指定）。</summary>
    public static async Task<VolumeInfo> CreateGroupVolumeAsync(this CistaNasApiClient client, string groupName,
        byte[] wrappedNonce, byte[] wrappedCt, byte[] wrappedTag, byte[] kdfSalt, KdfInfo kdf, int chunkSize = 1048576)
    {
        var http = client._http;
        var req = new
        {
            groupName,
            ownerWrappedKey = new
            {
                wrapType = "password",
                kdf = new
                {
                    algorithm = kdf.Algorithm,
                    iterations = kdf.Iterations,
                    memoryKiB = kdf.MemoryKiB,
                    timeCost = kdf.TimeCost,
                    parallelism = kdf.Parallelism,
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
}

/// <summary>グループメンバー情報。</summary>
public class GroupMemberInfo
{
    public required string Username { get; set; }
    public string? PublicKey { get; set; }
}

public static class CistaNasApiClientE2eeV2Extensions
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>
    /// crypto format v2: 自分宛ての全 epoch GroupKey wraps とボリューム鍵状態を取得する。
    /// 共有 v2 未移行ボリュームでは KeyEpoch == 0 / MyGroupKeys 空。
    /// </summary>
    public static async Task<E2eeGroupKeyInfo?> GetGroupKeyInfoAsync(this CistaNasApiClient client, string volumeName)
    {
        var http = client._http;
        var res = await http.GetAsync($"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/group-key-info");
        if (res.StatusCode == System.Net.HttpStatusCode.NotFound) return null;
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();

        var myKeys = new List<GroupKeyWrapInfo>();
        if (json.TryGetProperty("myGroupKeys", out var keys) && keys.ValueKind == JsonValueKind.Array)
        {
            foreach (var k in keys.EnumerateArray())
            {
                myKeys.Add(new GroupKeyWrapInfo
                {
                    Epoch = k.GetProperty("epoch").GetInt32(),
                    WrapType = k.TryGetProperty("wrapType", out var wt) ? wt.GetString() ?? "ecdh" : "ecdh",
                    Nonce = Convert.FromBase64String(k.GetProperty("nonce").GetString()!),
                    Ciphertext = Convert.FromBase64String(k.GetProperty("ciphertext").GetString()!),
                    Tag = Convert.FromBase64String(k.GetProperty("tag").GetString()!),
                    EphemeralPublicKey = k.TryGetProperty("ephemeralPublicKey", out var eph) && eph.ValueKind == JsonValueKind.String
                        ? Convert.FromBase64String(eph.GetString()!) : null,
                });
            }
        }

        return new E2eeGroupKeyInfo
        {
            VolumeId = json.GetProperty("volumeId").GetString()!,
            KeyEpoch = json.TryGetProperty("keyEpoch", out var ke) ? ke.GetInt32() : 0,
            MyGroupKeys = myKeys,
            HasLegacyFiles = json.TryGetProperty("hasLegacyFiles", out var hl) && hl.GetBoolean(),
        };
    }

    /// <summary>
    /// crypto format v2: GroupKey をローテーションする（revoke 時）。newGroupKeys は
    /// remaining members のユーザー名 → (nonce, ct, tag, ephemeralPublicKey)。
    /// </summary>
    public static async Task RotateGroupKeyAsync(this CistaNasApiClient client, string volumeName,
        int newEpoch, Dictionary<string, (byte[] nonce, byte[] ct, byte[] tag, byte[] ephemeralPublicKey)> newGroupKeys,
        string? removedUsername = null)
    {
        var http = client._http;
        var wrapped = new Dictionary<string, object>();
        foreach (var (username, (nonce, ct, tag, ephemeralPublicKey)) in newGroupKeys)
        {
            wrapped[username] = new
            {
                wrapType = "ecdh",
                kdf = new { algorithm = "pbkdf2-sha256", iterations = 0, salt = Array.Empty<byte>() },
                ephemeralPublicKey,
                wrappedMasterKey = new { algorithm = "aes-256-gcm", nonce, ciphertext = ct, tag }
            };
        }
        var req = new { newEpoch, wrappedGroupKeys = wrapped, removedUsername };
        var res = await http.PostAsJsonAsync($"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/rotate-group-key", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>crypto format v2: remaining members の公開鍵一覧を取得する（owner 限定）。</summary>
    public static async Task<List<MemberPublicKeyInfo>> GetMemberPublicKeysAsync(this CistaNasApiClient client, string volumeName)
    {
        var http = client._http;
        var res = await http.GetAsync($"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/member-public-keys");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        var result = new List<MemberPublicKeyInfo>();
        foreach (var m in json.EnumerateArray())
        {
            result.Add(new MemberPublicKeyInfo
            {
                Username = m.GetProperty("username").GetString()!,
                PublicKeyBase64 = m.TryGetProperty("publicKeyBase64", out var pk) ? pk.GetString() : null,
            });
        }
        return result;
    }

    /// <summary>crypto format v2: ファイル鍵を現行 epoch の GroupKey に再ラップする（チャンク本体は不変）。</summary>
    public static async Task RewrapFileKeysAsync(this CistaNasApiClient client, string volumeName,
        IReadOnlyList<(string fileId, int keyEpoch, WrappedAeadKey wrappedFileKey)> rewraps)
    {
        var http = client._http;
        var req = new
        {
            rewraps = rewraps.Select(r => new
            {
                fileId = r.fileId,
                keyEpoch = r.keyEpoch,
                wrappedFileKey = new
                {
                    algorithm = r.wrappedFileKey.Algorithm,
                    nonce = r.wrappedFileKey.Nonce,
                    ciphertext = r.wrappedFileKey.Ciphertext,
                    tag = r.wrappedFileKey.Tag
                }
            }).ToList()
        };
        var res = await http.PostAsJsonAsync($"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/rewrap-file-keys", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }
}
