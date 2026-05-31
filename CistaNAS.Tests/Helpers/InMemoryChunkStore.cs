using CistaNAS.Web.Storage;

namespace CistaNAS.Tests.Helpers;

/// <summary>
/// テスト用のインメモリ IChunkStore 実装。
/// </summary>
public sealed class InMemoryChunkStore : IChunkStore
{
    private readonly Dictionary<(string vol, string obj, int idx), byte[]> _chunks = new();

    public Task WriteChunkAsync(string volumeName, string objectId, int chunkIndex, Stream data, CancellationToken ct = default)
    {
        using var ms = new MemoryStream();
        data.CopyTo(ms);
        _chunks[(volumeName, objectId, chunkIndex)] = ms.ToArray();
        return Task.CompletedTask;
    }

    public Task<byte[]?> ReadChunkAsync(string volumeName, string objectId, int chunkIndex, CancellationToken ct = default)
    {
        _chunks.TryGetValue((volumeName, objectId, chunkIndex), out var data);
        return Task.FromResult(data);
    }

    public byte[]? ReadChunk(string volumeName, string objectId, int chunkIndex)
    {
        _chunks.TryGetValue((volumeName, objectId, chunkIndex), out var data);
        return data;
    }

    public Task<IReadOnlyList<int>> ListChunksAsync(string volumeName, string objectId, CancellationToken ct = default)
    {
        var indices = _chunks.Keys
            .Where(k => k.vol == volumeName && k.obj == objectId)
            .Select(k => k.idx)
            .OrderBy(i => i)
            .ToList();
        return Task.FromResult<IReadOnlyList<int>>(indices);
    }

    public Task DeleteChunksAsync(string volumeName, string objectId, CancellationToken ct = default)
    {
        foreach (var key in _chunks.Keys.Where(k => k.vol == volumeName && k.obj == objectId).ToList())
            _chunks.Remove(key);
        return Task.CompletedTask;
    }

    public Task DeleteVolumeChunksAsync(string volumeName, CancellationToken ct = default)
    {
        foreach (var key in _chunks.Keys.Where(k => k.vol == volumeName).ToList())
            _chunks.Remove(key);
        return Task.CompletedTask;
    }
}
