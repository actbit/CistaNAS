using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace CistaNAS.Client.Api;

/// <summary>
/// CistaNAS サーバーの /api/v1/e2ee エンドポイントにアクセスする HTTP クライアント。
/// </summary>
public sealed class CistaNasApiClient
{
    internal readonly HttpClient _http;
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public CistaNasApiClient(HttpClient http)
    {
        _http = http;
    }

    public void SetToken(string token)
    {
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    /// <summary>Authorization ヘッダーを除去する。</summary>
    public void ClearToken()
    {
        _http.DefaultRequestHeaders.Authorization = null;
    }

    // ---- 認証 ----

    public async Task<string> LoginAsync(string username, string password)
    {
        var res = await _http.PostAsJsonAsync("/api/v1/auth/login", new { username, password }, JsonOpts);
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("accessToken").GetString()!;
    }

    // ---- E2EE ボリューム ----

    public Task CreateVolumeAsync(string volumeName, string username,
        byte[] wrappedNonce, byte[] wrappedCt, byte[] wrappedTag,
        byte[] kdfSalt, int kdfIterations, int chunkSize = 1048576)
        => CreateVolumeAsync(volumeName, username, wrappedNonce, wrappedCt, wrappedTag,
            kdfSalt, KdfInfo.LegacyPbkdf2(kdfIterations), chunkSize);

    /// <summary>E2EE ボリュームを作成する（KDF スペック指定。新規は <see cref="KdfInfo.DefaultArgon2id"/> を使用）。</summary>
    public async Task CreateVolumeAsync(string volumeName, string username,
        byte[] wrappedNonce, byte[] wrappedCt, byte[] wrappedTag,
        byte[] kdfSalt, KdfInfo kdf, int chunkSize = 1048576)
    {
        var req = new
        {
            volumeName,
            username,
            wrappedMasterKey = new
            {
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
        var res = await _http.PostAsJsonAsync("/api/v1/e2ee/create-volume", req, JsonOpts);
        res.EnsureSuccessStatusCode();
    }

    public async Task MountAsync(string volumeName)
    {
        var res = await _http.PostAsJsonAsync($"/api/v1/e2ee/{volumeName}/mount", new { });
        res.EnsureSuccessStatusCode();
    }

    public async Task<WrappedKeyInfo> GetWrappedKeyAsync(string volumeName, string username)
    {
        var res = await _http.GetAsync($"/api/v1/e2ee/{volumeName}/wrapped-key/{username}");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();

        var kdf = json.GetProperty("kdf");
        var wk = json.GetProperty("wrappedMasterKey");

        return new WrappedKeyInfo
        {
            KdfAlgorithm = kdf.GetProperty("algorithm").GetString()!,
            KdfIterations = kdf.GetProperty("iterations").GetInt32(),
            KdfMemoryKiB = kdf.TryGetProperty("memoryKiB", out var mk) && mk.ValueKind == JsonValueKind.Number ? mk.GetInt32() : 0,
            KdfTimeCost = kdf.TryGetProperty("timeCost", out var tc) && tc.ValueKind == JsonValueKind.Number ? tc.GetInt32() : 0,
            KdfParallelism = kdf.TryGetProperty("parallelism", out var pl) && pl.ValueKind == JsonValueKind.Number ? pl.GetInt32() : 0,
            KdfSalt = Convert.FromBase64String(kdf.GetProperty("salt").GetString()!),
            WrapType = json.TryGetProperty("wrapType", out var wt) && wt.ValueKind == JsonValueKind.String
                ? wt.GetString() : "password",
            EphemeralPublicKey = json.TryGetProperty("ephemeralPublicKey", out var eph) && eph.ValueKind == JsonValueKind.String
                ? Convert.FromBase64String(eph.GetString()!) : null,
            WrappedNonce = Convert.FromBase64String(wk.GetProperty("nonce").GetString()!),
            WrappedCiphertext = Convert.FromBase64String(wk.GetProperty("ciphertext").GetString()!),
            WrappedTag = Convert.FromBase64String(wk.GetProperty("tag").GetString()!),
            ChunkSize = json.TryGetProperty("chunkSize", out var cs) ? cs.GetInt32() : 1048576,
        };
    }

    public async Task<(string FileId, string WriteLeaseToken)> CreateFileAsync(
        string volumeName, string encryptedName, long encryptedLength, int chunkCount)
        => await CreateFileAsync(volumeName, encryptedName, encryptedLength, chunkCount,
            keyEpoch: 0, wrappedFileKey: null);

    /// <summary>E2EE ファイルを作成する（crypto format v2: KeyEpoch ≥ 1 の場合はラップ済み DEK が必須）。</summary>
    public async Task<(string FileId, string WriteLeaseToken)> CreateFileAsync(
        string volumeName, string encryptedName, long encryptedLength, int chunkCount,
        int keyEpoch, WrappedAeadKey? wrappedFileKey, string? fileId = null)
    {
        var req = new
        {
            encryptedName,
            encryptedLength,
            chunkCount,
            keyEpoch,
            wrappedFileKey = wrappedFileKey is null
                ? null
                : new { algorithm = wrappedFileKey.Algorithm, nonce = wrappedFileKey.Nonce, ciphertext = wrappedFileKey.Ciphertext, tag = wrappedFileKey.Tag },
            fileId
        };
        var res = await _http.PostAsJsonAsync($"/api/v1/e2ee/{volumeName}/create-file", req, JsonOpts);
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return (json.GetProperty("fileId").GetString()!, json.GetProperty("writeLeaseToken").GetString()!);
    }

    public async Task<string> AcquireWriteLeaseAsync(string volumeName, string fileId)
    {
        var res = await _http.PostAsync($"/api/v1/e2ee/{volumeName}/files/{fileId}/write-lease", null);
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("token").GetString()!;
    }

    public async Task RenewWriteLeaseAsync(string volumeName, string fileId, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post,
            $"/api/v1/e2ee/{volumeName}/files/{fileId}/write-lease/renew");
        request.Headers.Add("X-CistaNAS-Write-Lease", token);
        var res = await _http.SendAsync(request);
        res.EnsureSuccessStatusCode();
    }

    public async Task ReleaseWriteLeaseAsync(string volumeName, string fileId, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete,
            $"/api/v1/e2ee/{volumeName}/files/{fileId}/write-lease");
        request.Headers.Add("X-CistaNAS-Write-Lease", token);
        var res = await _http.SendAsync(request);
        res.EnsureSuccessStatusCode();
    }

    public async Task UploadChunkAsync(string volumeName, string fileId, int chunkIndex, byte[] data, string writeLeaseToken, bool replace = false)
    {
        var content = new ByteArrayContent(data);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        var query = replace ? "?replace=true" : "";
        using var request = new HttpRequestMessage(HttpMethod.Post,
            $"/api/v1/e2ee/{volumeName}/upload-chunk/{fileId}/{chunkIndex}{query}") { Content = content };
        request.Headers.Add("X-CistaNAS-Write-Lease", writeLeaseToken);
        var res = await _http.SendAsync(request);
        res.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// チャンクをダウンロードする。Revision は差分上書き番号、KeyEpoch は crypto format v2 の
    /// このチャンクの暗号化時 keyEpoch（v1 では 0、旧サーバーではヘッダ欠如で 0）。
    /// v2 チャンクの nonce / AAD は (chunkIndex, revision, keyEpoch) を bind するため復号に必須。
    /// </summary>
    public async Task<(byte[] Data, int Revision, int KeyEpoch)> DownloadChunkAsync(string volumeName, string fileId, int chunkIndex)
    {
        var res = await _http.GetAsync($"/api/v1/e2ee/{volumeName}/download-chunk/{fileId}/{chunkIndex}");
        res.EnsureSuccessStatusCode();
        byte[] data = await res.Content.ReadAsByteArrayAsync();
        int revision = 0;
        if (res.Headers.TryGetValues("X-Chunk-Revision", out var vals))
        {
            var v = vals.FirstOrDefault();
            if (v is not null && int.TryParse(v, out int rev)) revision = rev;
        }
        int keyEpoch = 0;
        if (res.Headers.TryGetValues("X-Chunk-KeyEpoch", out var epochVals))
        {
            var v = epochVals.FirstOrDefault();
            if (v is not null && int.TryParse(v, out int epoch)) keyEpoch = epoch;
        }
        return (data, revision, keyEpoch);
    }

    /// <summary>チャンクの事前計算ハッシュと revision を取得する（軽量エンドポイント）。ハッシュなしの場合は (null, 0)。</summary>
    public async Task<(string? Hash, int Revision)> GetChunkHashAsync(string volumeName, string fileId, int chunkIndex)
    {
        var res = await _http.GetAsync($"/api/v1/e2ee/{volumeName}/chunk-hash/{fileId}/{chunkIndex}");
        if (res.StatusCode == System.Net.HttpStatusCode.NotFound)
            return (null, 0);
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        string? hash = json.TryGetProperty("hash", out var h) ? h.GetString() : null;
        int revision = json.TryGetProperty("revision", out var r) ? r.GetInt32() : 0;
        return (hash, revision);
    }

    public async Task FinalizeFileAsync(string volumeName, string fileId, long actualLength, string writeLeaseToken, int? chunkCount = null)
    {
        var req = new { actualEncryptedLength = actualLength, chunkCount };
        using var request = new HttpRequestMessage(HttpMethod.Patch,
            $"/api/v1/e2ee/{volumeName}/finalize-file/{fileId}") { Content = JsonContent.Create(req, options: JsonOpts) };
        request.Headers.Add("X-CistaNAS-Write-Lease", writeLeaseToken);
        var res = await _http.SendAsync(request);
        res.EnsureSuccessStatusCode();
    }

    public async Task DeleteFileAsync(string volumeName, string fileId, string writeLeaseToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, $"/api/v1/e2ee/{volumeName}/files/{fileId}");
        request.Headers.Add("X-CistaNAS-Write-Lease", writeLeaseToken);
        var res = await _http.SendAsync(request);
        res.EnsureSuccessStatusCode();
    }

    public async Task<List<E2eeFileEntry>> ListFilesAsync(string volumeName)
    {
        var res = await _http.GetAsync($"/api/v1/e2ee/{volumeName}/files");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        var files = json.GetProperty("files");
        var result = new List<E2eeFileEntry>();
        foreach (var f in files.EnumerateArray())
        {
            result.Add(new E2eeFileEntry
            {
                FileId = f.GetProperty("fileId").GetString()!,
                EncryptedName = f.GetProperty("encryptedName").GetString()!,
                EncryptedLength = f.GetProperty("encryptedLength").GetInt64(),
                ChunkCount = f.GetProperty("chunkCount").GetInt32(),
                KeyEpoch = f.TryGetProperty("keyEpoch", out var ke) && ke.ValueKind == JsonValueKind.Number ? ke.GetInt32() : 0,
                WrappedFileKey = E2eeJsonParsers.ParseWrappedAeadKey(f, "wrappedFileKey"),
                CreatedAt = f.GetProperty("createdAt").GetDateTimeOffset(),
                ModifiedAt = f.GetProperty("modifiedAt").GetDateTimeOffset(),
            });
        }
        return result;
    }

    public async Task<List<VolumeListItem>> ListVolumesAsync()
    {
        var res = await _http.GetAsync("/api/v1/volumes");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        var result = new List<VolumeListItem>();
        if (json.ValueKind == JsonValueKind.Array)
        {
            foreach (var v in json.EnumerateArray())
            {
                result.Add(new VolumeListItem
                {
                    Name = v.GetProperty("name").GetString()!,
                    Encrypted = v.TryGetProperty("encrypted", out var enc) && enc.GetBoolean(),
                    EncryptionMode = v.TryGetProperty("encryptionMode", out var mode) ? mode.GetString() ?? "server" : "server",
                    CipherAlgorithm = v.TryGetProperty("cipherAlgorithm", out var cipher) ? cipher.GetString() ?? "aes-256-xts" : "aes-256-xts",
                    KeySize = v.TryGetProperty("keySize", out var keySize) ? keySize.GetInt32() : 256,
                    IsMounted = v.TryGetProperty("isMounted", out var mnt) && mnt.GetBoolean(),
                    OwnerUser = v.TryGetProperty("ownerUser", out var owner) ? owner.GetString() ?? "" : "",
                });
            }
        }
        return result;
    }

    public async Task<VolumeStats> GetVolumeStatsAsync(string volumeName)
    {
        var res = await _http.GetAsync($"/api/v1/e2ee/{volumeName}/stats");
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadFromJsonAsync<JsonElement>();
        return new VolumeStats
        {
            TotalUsedBytes = json.GetProperty("totalUsedBytes").GetInt64(),
            UserUsedBytes = json.GetProperty("userUsedBytes").GetInt64(),
            UserQuotaBytes = json.GetProperty("userQuotaBytes").GetInt64(),
            TotalFiles = json.GetProperty("totalFiles").GetInt32(),
            UserFiles = json.GetProperty("userFiles").GetInt32(),
        };
    }
}

public class E2eeFileEntry
{
    public required string FileId { get; set; }
    public required string EncryptedName { get; set; }
    public long EncryptedLength { get; set; }
    public int ChunkCount { get; set; }
    /// <summary>crypto format v2: このファイルの鍵 epoch。0 = v1 形式（masterKey 派生 fileKey）。</summary>
    public int KeyEpoch { get; set; }
    /// <summary>crypto format v2: per-file DEK を GroupKey[KeyEpoch] でラップしたもの。KeyEpoch == 0 では null。</summary>
    public WrappedAeadKey? WrappedFileKey { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }
}

/// <summary>crypto format v2: AEAD ラップされた鍵（algorithm / nonce / ciphertext / tag、base64）。</summary>
public class WrappedAeadKey
{
    public required string Algorithm { get; set; }
    public required byte[] Nonce { get; set; }
    public required byte[] Ciphertext { get; set; }
    public required byte[] Tag { get; set; }
}

/// <summary>crypto format v2: 自分宛てにラップされた GroupKey（epoch 単位）。</summary>
public class GroupKeyWrapInfo
{
    public int Epoch { get; set; }
    public string WrapType { get; set; } = "ecdh";
    public required byte[] Nonce { get; set; }
    public required byte[] Ciphertext { get; set; }
    public required byte[] Tag { get; set; }
    public byte[]? EphemeralPublicKey { get; set; }
}

/// <summary>crypto format v2: ボリュームの GroupKey 状態（group-key-info 応答）。</summary>
public class E2eeGroupKeyInfo
{
    public required string VolumeId { get; set; }
    public int KeyEpoch { get; set; }
    public List<GroupKeyWrapInfo> MyGroupKeys { get; set; } = [];
    public bool HasLegacyFiles { get; set; }
}

/// <summary>crypto format v2: remaining members の公開鍵（member-public-keys 応答）。</summary>
public class MemberPublicKeyInfo
{
    public required string Username { get; set; }
    public string? PublicKeyBase64 { get; set; }
}

internal static partial class E2eeJsonParsers
{
    /// <summary>camelCase プロパティ下の {algorithm, nonce, ciphertext, tag} を WrappedAeadKey としてパース。無ければ null。</summary>
    public static WrappedAeadKey? ParseWrappedAeadKey(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var w) || w.ValueKind != JsonValueKind.Object)
            return null;
        if (!w.TryGetProperty("nonce", out var n) || n.ValueKind != JsonValueKind.String)
            return null;
        return new WrappedAeadKey
        {
            Algorithm = w.TryGetProperty("algorithm", out var a) ? a.GetString() ?? "aes-256-gcm" : "aes-256-gcm",
            Nonce = Convert.FromBase64String(n.GetString()!),
            Ciphertext = Convert.FromBase64String(w.GetProperty("ciphertext").GetString()!),
            Tag = Convert.FromBase64String(w.GetProperty("tag").GetString()!),
        };
    }
}

/// <summary>
/// パスワードベース KDF のパラメータ（サーバー VolumeHeader.KdfParams と同型）。
/// Algorithm == "argon2id" は合成 KDF: KEK = PBKDF2-SHA256(Argon2id(pw, salt, t, m, p), salt, Iterations, 32)。
/// Algorithm == "argon2id-raw" は Argon2id 単独（PBKDF2 後段なし。Iterations 不使用）。
/// </summary>
public sealed record KdfInfo(string Algorithm, int Iterations, int MemoryKiB, int TimeCost, int Parallelism)
{
    public const string Argon2id = "argon2id";
    public const string Argon2idRaw = "argon2id-raw";
    public const string Pbkdf2Sha256 = "pbkdf2-sha256";

    /// <summary>新規作成時の既定: Argon2id(m=64MiB, t=4, p=4) + PBKDF2(600k) 合成。</summary>
    public static KdfInfo DefaultArgon2id { get; } = new(Argon2id, 600_000, 65536, 4, 4);

    /// <summary>Argon2id 単独の既定スペック（m=64MiB, t=4, p=4。PBKDF2 後段なし）。</summary>
    public static KdfInfo DefaultArgon2idRaw { get; } = new(Argon2idRaw, 0, 65536, 4, 4);

    /// <summary>レガシー PBKDF2 単段スペック（既存データの検証用）。</summary>
    public static KdfInfo LegacyPbkdf2(int iterations) => new(Pbkdf2Sha256, iterations, 0, 0, 0);
}

public class VolumeListItem
{
    public required string Name { get; set; }
    public bool Encrypted { get; set; }
    public string EncryptionMode { get; set; } = "server";
    public string CipherAlgorithm { get; set; } = "aes-256-xts";
    public int KeySize { get; set; } = 256;
    public bool IsMounted { get; set; }
    public string OwnerUser { get; set; } = "";
}

public class VolumeStats
{
    public long TotalUsedBytes { get; set; }
    public long UserUsedBytes { get; set; }
    public long UserQuotaBytes { get; set; }
    public int TotalFiles { get; set; }
    public int UserFiles { get; set; }
}

public class WrappedKeyInfo
{
    public required string KdfAlgorithm { get; set; }
    public required int KdfIterations { get; set; }
    /// <summary>argon2id 前段のメモリ量 (KiB)。レガシー pbkdf2-sha256 では 0。</summary>
    public int KdfMemoryKiB { get; set; }
    /// <summary>argon2id 前段のパス数 (t)。レガシー pbkdf2-sha256 では 0。</summary>
    public int KdfTimeCost { get; set; }
    /// <summary>argon2id 前段の並列度。レガシー pbkdf2-sha256 では 0。</summary>
    public int KdfParallelism { get; set; }
    public required byte[] KdfSalt { get; set; }
    /// <summary>"password" or "ecdh"。未指定時は password。</summary>
    public string? WrapType { get; set; }
    /// <summary>ECDH ラップキーの一時公開鍵（raw 65B）。password ラップ時は null。</summary>
    public byte[]? EphemeralPublicKey { get; set; }
    public required byte[] WrappedNonce { get; set; }
    public required byte[] WrappedCiphertext { get; set; }
    public required byte[] WrappedTag { get; set; }
    public int ChunkSize { get; set; } = 1048576;
}
