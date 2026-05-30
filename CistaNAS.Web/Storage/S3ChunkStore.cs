namespace CistaNAS.Web.Storage;

/// <summary>
/// IStorageProvider 経由でチャンクを保存する IChunkStore 実装。
/// キーパターン: {volumeName}/chunks/{objectId}/{chunkIndex:00000}
/// chunkIndex は5桁ゼロ埋めでソート順を保証。
/// </summary>
public sealed class S3ChunkStore : IChunkStore
{
    private readonly IStorageProvider _storage;

    public S3ChunkStore(IStorageProvider storage)
    {
        _storage = storage;
    }

    private static string ChunkKey(string volumeName, string objectId, int chunkIndex)
        => $"{volumeName}/chunks/{objectId}/{chunkIndex:D5}";

    public Task WriteChunkAsync(string volumeName, string objectId, int chunkIndex, Stream data, CancellationToken ct = default)
        => _storage.WriteAsync(ChunkKey(volumeName, objectId, chunkIndex), data, ct);

    public Task<byte[]?> ReadChunkAsync(string volumeName, string objectId, int chunkIndex, CancellationToken ct = default)
        => _storage.ReadAsync(ChunkKey(volumeName, objectId, chunkIndex), ct);

    public async Task<IReadOnlyList<int>> ListChunksAsync(string volumeName, string objectId, CancellationToken ct = default)
    {
        string prefix = $"{volumeName}/chunks/{objectId}/";
        var keys = await _storage.ListAsync(prefix, ct);
        var indices = new List<int>(keys.Count);
        foreach (var key in keys)
        {
            // キー末尾の5桁インデックスを抽出
            int slash = key.LastIndexOf('/');
            if (slash < 0 || slash == key.Length - 1) continue;
            string idxStr = key[(slash + 1)..];
            if (int.TryParse(idxStr, out int idx))
                indices.Add(idx);
        }
        indices.Sort();
        return indices;
    }

    public async Task DeleteChunksAsync(string volumeName, string objectId, CancellationToken ct = default)
    {
        string prefix = $"{volumeName}/chunks/{objectId}/";
        var keys = await _storage.ListAsync(prefix, ct);
        foreach (var key in keys)
        {
            try { await _storage.DeleteAsync(key, ct); }
            catch (Exception) { /* ベストエフォート */ }
        }
    }

    public async Task DeleteVolumeChunksAsync(string volumeName, CancellationToken ct = default)
    {
        string prefix = $"{volumeName}/chunks/";
        var keys = await _storage.ListAsync(prefix, ct);
        foreach (var key in keys)
        {
            try { await _storage.DeleteAsync(key, ct); }
            catch (Exception) { /* ベストエフォート */ }
        }
    }
}
