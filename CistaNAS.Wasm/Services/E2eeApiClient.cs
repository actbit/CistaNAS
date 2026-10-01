using System.Net.Http.Json;
using CistaNAS.Wasm.Models;

namespace CistaNAS.Wasm.Services;

/// <summary>E2EE ファイル API クライアント。</summary>
public sealed class E2eeApiClient
{
    private readonly HttpClient _http;

    public E2eeApiClient(HttpClient http) => _http = http;

    /// <summary>E2EE ファイル作成（v1 形式: KeyEpoch == 0）。</summary>
    public Task<E2eeFileEntry> CreateFileAsync(string volumeName, string encryptedName, long encryptedLength, int chunkCount, CancellationToken ct = default)
        => CreateFileAsync(volumeName, encryptedName, encryptedLength, chunkCount, keyEpoch: 0, wrappedFileKey: null, fileId: null, ct: ct);

    /// <summary>E2EE ファイル作成（crypto format v2: KeyEpoch ≥ 1 の場合はラップ済み DEK が必須）。
    /// fileId にはクライアント生成 GUID "N" 形式を指定可能（WrappedFileKey の AAD bind 用）。</summary>
    public async Task<E2eeFileEntry> CreateFileAsync(
        string volumeName, string encryptedName, long encryptedLength, int chunkCount,
        int keyEpoch, WrappedAeadKeyParams? wrappedFileKey, string? fileId, CancellationToken ct = default)
    {
        using var response = await _http.PostAsJsonAsync(
            $"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/create-file",
            new E2eeCreateFileRequest(encryptedName, encryptedLength, chunkCount, keyEpoch, wrappedFileKey, fileId), ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<E2eeFileEntry>(ct))!;
    }

    public async Task<string> AcquireWriteLeaseAsync(string volumeName, string fileId, CancellationToken ct = default)
    {
        using var response = await _http.PostAsync(
            $"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/files/{Uri.EscapeDataString(fileId)}/write-lease", null, ct);
        response.EnsureSuccessStatusCode();
        var lease = await response.Content.ReadFromJsonAsync<WriteLeaseResponse>(ct);
        return lease?.Token ?? throw new InvalidDataException("書き込みリースtokenがありません。");
    }

    public async Task ReleaseWriteLeaseAsync(string volumeName, string fileId, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete,
            $"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/files/{Uri.EscapeDataString(fileId)}/write-lease");
        request.Headers.Add("X-CistaNAS-Write-Lease", token);
        using var response = await _http.SendAsync(request);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>チャンクアップロード。</summary>
    public async Task UploadChunkAsync(string volumeName, string fileId, int chunkIndex, byte[] data, string writeLeaseToken,
        CancellationToken ct = default, int keyEpoch = 0)
    {
        using var content = new ByteArrayContent(data);
        using var request = new HttpRequestMessage(HttpMethod.Post,
            $"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/upload-chunk/{Uri.EscapeDataString(fileId)}/{chunkIndex}")
        { Content = content };
        request.Headers.Add("X-CistaNAS-Write-Lease", writeLeaseToken);
        request.Headers.Add("X-Chunk-KeyEpoch", keyEpoch.ToString(System.Globalization.CultureInfo.InvariantCulture));
        using var response = await _http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>チャンクダウンロード。nonce 導出に必要な X-Chunk-Revision と、v2 復号に必要な
    /// X-Chunk-KeyEpoch（チャンク暗号化時の keyEpoch、旧サーバーでは欠如 → 0）も返す。</summary>
    public async Task<(byte[] Data, int Revision, int KeyEpoch)> DownloadChunkAsync(string volumeName, string fileId, int chunkIndex, CancellationToken ct = default)
    {
        using var response = await _http.GetAsync(
            $"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/download-chunk/{Uri.EscapeDataString(fileId)}/{chunkIndex}", ct);
        response.EnsureSuccessStatusCode();
        byte[] data = await response.Content.ReadAsByteArrayAsync(ct);
        int revision = 0;
        if (response.Headers.TryGetValues("X-Chunk-Revision", out var vals))
        {
            var v = vals.FirstOrDefault();
            if (v is not null && int.TryParse(v, out int rev)) revision = rev;
        }
        int keyEpoch = 0;
        if (response.Headers.TryGetValues("X-Chunk-KeyEpoch", out var epochVals))
        {
            var v = epochVals.FirstOrDefault();
            if (v is not null && int.TryParse(v, out int epoch)) keyEpoch = epoch;
        }
        return (data, revision, keyEpoch);
    }

    /// <summary>チャンクハッシュ取得。</summary>
    public async Task<string?> GetChunkHashAsync(string volumeName, string fileId, int chunkIndex)
    {
        var response = await _http.GetAsync(
            $"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/chunk-hash/{Uri.EscapeDataString(fileId)}/{chunkIndex}");
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<HashResponse>();
        return result?.Hash;
    }

    /// <summary>ファイルファイナライズ。</summary>
    public async Task FinalizeFileAsync(string volumeName, string fileId, long actualEncryptedLength, string writeLeaseToken, int? chunkCount = null, CancellationToken ct = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Patch,
            $"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/finalize-file/{Uri.EscapeDataString(fileId)}")
        { Content = JsonContent.Create(new E2eeFinalizeFileRequest(actualEncryptedLength, chunkCount)) };
        request.Headers.Add("X-CistaNAS-Write-Lease", writeLeaseToken);
        using var response = await _http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>ファイル一覧。</summary>
    public async Task<E2eeListFilesResponse> ListFilesAsync(string volumeName, CancellationToken ct = default)
    {
        var result = await _http.GetFromJsonAsync<E2eeListFilesResponse>(
            $"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/files", ct);
        return result ?? new E2eeListFilesResponse([]);
    }

    /// <summary>ファイル削除。</summary>
    public async Task DeleteFileAsync(string volumeName, string fileId, string writeLeaseToken, CancellationToken ct = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete,
            $"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/files/{Uri.EscapeDataString(fileId)}");
        request.Headers.Add("X-CistaNAS-Write-Lease", writeLeaseToken);
        using var response = await _http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>ボリューム使用量統計。</summary>
    public async Task<E2eeVolumeStats> GetStatsAsync(string volumeName)
    {
        var result = await _http.GetFromJsonAsync<E2eeVolumeStats>(
            $"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/stats");
        return result!;
    }

    /// <summary>ユーザークオータ設定。</summary>
    public async Task SetQuotaAsync(string volumeName, string username, long maxBytes)
    {
        var response = await _http.PutAsync(
            $"/api/v1/e2ee/{Uri.EscapeDataString(volumeName)}/quota/{Uri.EscapeDataString(username)}",
            JsonContent.Create(new E2eeSetQuotaRequest(maxBytes)));
        response.EnsureSuccessStatusCode();
    }

    /// <summary>招待を作成する。</summary>
    public async Task<string> CreateInvitationAsync(string targetUsername)
    {
        var response = await _http.PostAsJsonAsync("/api/v1/e2ee/invitations",
            new CreateInvitationRequest(targetUsername));
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<InvitationIdResponse>();
        return result?.InvitationId ?? "";
    }

    /// <summary>
    /// 決定論的 ECDH identity のセットアップ情報を取得する（identity salt は非秘密）。
    /// 秘密鍵はクライアント側で E2EE パスワードから導出し、サーバーへは送らない。
    /// 共有機能が無効なアカウントでは 403 → null。
    /// </summary>
    public async Task<E2eeIdentitySetupInfo?> GetIdentitySetupAsync(CancellationToken ct = default)
    {
        using var response = await _http.GetAsync("/api/v1/e2ee/identity-setup", ct);
        if (!response.IsSuccessStatusCode) return null;
        return await response.Content.ReadFromJsonAsync<E2eeIdentitySetupInfo>(ct);
    }

    /// <summary>自分の公開鍵を登録する。既存鍵の更新（rotation）は rotate=true を必須とする
    /// （誤った E2EE パスワードからの導出結果で既存 identity を上書きしないため）。</summary>
    public async Task SetMyPublicKeyAsync(string publicKey, bool rotate = false)
    {
        var response = await _http.PutAsJsonAsync(
            $"/api/v1/e2ee/my-public-key{(rotate ? "?rotate=true" : "")}",
            new { PublicKey = publicKey });
        response.EnsureSuccessStatusCode();
    }

    public sealed record E2eeIdentitySetupInfo(
        byte[] IdentitySalt, int DerivationVersion, string? PublicKey, E2eeKdfOptions Kdf);

    private sealed record HashResponse(string Hash);
    private sealed record InvitationIdResponse(string InvitationId);
    private sealed record WriteLeaseResponse(string Token, DateTimeOffset ExpiresAt);
}
