using System.Text.Json;

namespace CistaNAS.Web.Storage;

/// <summary>新規ボリュームの空カタログを作成する共通ヘルパー。</summary>
internal static class CatalogStorage
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static Task InitializeEmptyAsync(
        IStorageProvider storage, string volumeName, bool e2ee, CancellationToken ct = default)
    {
        using var ms = new MemoryStream();
        JsonSerializer.Serialize(ms, new EmptyCatalog(), JsonOptions);
        ms.Position = 0;
        string fileName = e2ee ? "catalog-e2ee.json" : "catalog.json";
        return storage.WriteAtomicAsync($"{volumeName}/{fileName}", ms, ct);
    }

    private sealed class EmptyCatalog
    {
        public Dictionary<string, object> Files { get; } = new(StringComparer.Ordinal);
    }
}
