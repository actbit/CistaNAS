using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CistaNAS.Web.Storage;

namespace CistaNAS.Web.Services;

/// <summary>
/// E2EE ファイルIDをキーにした、期限付きの排他書き込みリース。
/// ファイル名は扱わず、全インスタンスが共有する IStorageProvider 上のレコードで管理する。
/// </summary>
public sealed class E2eeWriteLeaseService(IStorageProvider storage)
{
    public const string HeaderName = "X-CistaNAS-Write-Lease";
    private static readonly TimeSpan LeaseDuration = TimeSpan.FromMinutes(2);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<WriteLease> AcquireAsync(string volumeName, string fileId, CancellationToken ct = default)
    {
        ValidateFileId(fileId);
        await using var guard = await AcquireGuardAsync(volumeName, fileId, ct);
        var current = await ReadAsync(volumeName, fileId, ct);
        var now = DateTimeOffset.UtcNow;
        if (current is not null && current.ExpiresAt > now)
            throw E2eeWriteLeaseException.Conflict();

        var lease = new WriteLease(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)), now.Add(LeaseDuration));
        await WriteAsync(volumeName, fileId, lease, ct);
        return lease;
    }

    /// <summary>token を検証し、書き込み継続中であれば有効期限を延長する。</summary>
    public async Task ValidateAndRenewAsync(string volumeName, string fileId, string? token, CancellationToken ct = default)
    {
        ValidateFileId(fileId);
        if (string.IsNullOrWhiteSpace(token))
            throw E2eeWriteLeaseException.Missing();

        await using var guard = await AcquireGuardAsync(volumeName, fileId, ct);
        var current = await ReadAsync(volumeName, fileId, ct);
        if (current is null || current.ExpiresAt <= DateTimeOffset.UtcNow ||
            !CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(current.Token), Encoding.UTF8.GetBytes(token)))
            throw E2eeWriteLeaseException.Invalid();

        var renewed = current with { ExpiresAt = DateTimeOffset.UtcNow.Add(LeaseDuration) };
        await WriteAsync(volumeName, fileId, renewed, ct);
    }

    public async Task ReleaseAsync(string volumeName, string fileId, string? token, CancellationToken ct = default)
    {
        ValidateFileId(fileId);
        if (string.IsNullOrWhiteSpace(token)) return;

        await using var guard = await AcquireGuardAsync(volumeName, fileId, ct);
        var current = await ReadAsync(volumeName, fileId, ct);
        if (current is not null &&
            CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(current.Token), Encoding.UTF8.GetBytes(token)))
            await storage.DeleteAsync(LeasePath(volumeName, fileId), ct);
    }

    private async Task<IAsyncDisposable> AcquireGuardAsync(string volumeName, string fileId, CancellationToken ct)
        => new SyncDisposableAdapter(await storage.AcquireLockAsync(GuardPath(volumeName, fileId), ct));

    private async Task<WriteLease?> ReadAsync(string volumeName, string fileId, CancellationToken ct)
    {
        var bytes = await storage.ReadAsync(LeasePath(volumeName, fileId), ct);
        if (bytes is null) return null;
        try { return JsonSerializer.Deserialize<WriteLease>(bytes, JsonOptions); }
        catch (JsonException) { return null; }
    }

    private Task WriteAsync(string volumeName, string fileId, WriteLease lease, CancellationToken ct)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(lease, JsonOptions);
        return storage.WriteAtomicAsync(LeasePath(volumeName, fileId), new MemoryStream(bytes), ct);
    }

    private static string LeasePath(string volumeName, string fileId)
        => $".write-leases/e2ee/{Uri.EscapeDataString(volumeName)}/{Uri.EscapeDataString(fileId)}.json";

    private static string GuardPath(string volumeName, string fileId)
        => $"e2ee-write-lease/{Uri.EscapeDataString(volumeName)}/{Uri.EscapeDataString(fileId)}";

    private static void ValidateFileId(string fileId)
    {
        if (!Guid.TryParseExact(fileId, "N", out _))
            throw new E2eeWriteLeaseException("fileIdが不正です。", StatusCodes.Status400BadRequest);
    }

    private sealed class SyncDisposableAdapter(IDisposable inner) : IAsyncDisposable
    {
        public ValueTask DisposeAsync()
        {
            inner.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

public sealed record WriteLease(string Token, DateTimeOffset ExpiresAt);

public sealed class E2eeWriteLeaseException(string message, int statusCode) : Exception(message)
{
    public int StatusCode { get; } = statusCode;
    public static E2eeWriteLeaseException Missing() => new("書き込みリースtokenが必要です。", StatusCodes.Status423Locked);
    public static E2eeWriteLeaseException Conflict() => new("このファイルは別のクライアントが書き込み中です。", StatusCodes.Status423Locked);
    public static E2eeWriteLeaseException Invalid() => new("書き込みリースが無効または期限切れです。", StatusCodes.Status423Locked);
}
