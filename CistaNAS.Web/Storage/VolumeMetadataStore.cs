using System.Text.Json;
using CistaNAS.Web.Volume;

namespace CistaNAS.Web.Storage;

/// <summary>IStorageProvider 経由で VolumeHeader を読み書きするヘルパー。</summary>
public sealed class VolumeMetadataStore(IStorageProvider storage)
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public async Task<VolumeHeader?> LoadAsync(string volumeName, CancellationToken ct = default)
    {
        byte[]? data = await storage.ReadAsync($"{volumeName}/{VolumeHeader.FileName}", ct);
        if (data is null) return null;
        return JsonSerializer.Deserialize<VolumeHeader>(data, JsonOptions);
    }

    public async Task SaveAsync(string volumeName, VolumeHeader header, CancellationToken ct = default)
    {
        using var ms = new MemoryStream();
        JsonSerializer.Serialize(ms, header, JsonOptions);
        ms.Position = 0;
        await storage.WriteAtomicAsync($"{volumeName}/{VolumeHeader.FileName}", ms, ct);
    }

    public async Task<bool> ExistsAsync(string volumeName, CancellationToken ct = default)
        => await storage.ExistsAsync($"{volumeName}/{VolumeHeader.FileName}", ct);

    public async Task<IReadOnlyList<string>> ListVolumeNamesAsync(CancellationToken ct = default)
    {
        var blobs = await storage.ListAsync(ct: ct);
        var volumes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var blob in blobs)
        {
            int slash = blob.IndexOf('/');
            if (slash < 0) continue;
            string dir = blob[..slash];
            if (blob[slash..] == $"/{VolumeHeader.FileName}")
                volumes.Add(dir);
        }
        return volumes.ToList();
    }

    public async Task DeleteAsync(string volumeName, CancellationToken ct = default)
        => await storage.DeleteAsync($"{volumeName}/{VolumeHeader.FileName}", ct);

    /// <summary>ボリュームの全メタデータ（volume.json, catalog, journal 等）を削除。</summary>
    public async Task DeleteAllAsync(string volumeName, CancellationToken ct = default)
    {
        var blobs = await storage.ListAsync($"{volumeName}/", ct);
        foreach (var blob in blobs)
            await storage.DeleteAsync(blob, ct);
    }
}
