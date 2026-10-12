using System.Text.Json;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Storage;

/// <summary>
/// カタログから参照されないチャンクを、保留期間と再参照確認付きで回収する。
/// カタログ・ジャーナル・候補台帳の読み取りに失敗した場合は削除を行わない。
/// </summary>
public sealed class ChunkGarbageCollector
{
    private const string CandidateFileName = "chunk-gc-candidates.json";
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly VolumeService _volumeService;
    private readonly JournalService _journalService;
    private readonly IStorageProvider _storage;
    private readonly IChunkStore _chunkStore;
    private readonly TimeSpan _holdPeriod;

    public ChunkGarbageCollector(
        VolumeService volumeService,
        JournalService journalService,
        IStorageProvider storage,
        IChunkStore chunkStore,
        IOptions<CistaNasOptions> options)
    {
        _volumeService = volumeService;
        _journalService = journalService;
        _storage = storage;
        _chunkStore = chunkStore;
        _holdPeriod = TimeSpan.FromHours(options.Value.Volume.ChunkGcHoldHours);
    }

    public async Task<ChunkGcReport> CollectAsync(
        string volumeName, bool dryRun = true, CancellationToken ct = default)
    {
        // GCはカタログ・ジャーナル・チャンクストアだけを扱うため、
        // パスワードを要求するサーバー暗号化Volumeも、マウントせずに安全に実行できる。
        // ヘッダは保存先から取得し、存在しない／壊れている場合は削除を行わない。
        var header = await _volumeService.GetStoredHeaderAsync(volumeName, ct);
        if (!string.Equals(header.StorageMode, "chunk", StringComparison.Ordinal))
            throw new FileServiceException("ローカルストレージのボリュームは孤児チャンクGCの対象外です。");

        string catalogLockName = header.IsE2ee ? "catalog-e2ee" : "catalog";
        using var catalogLock = await _storage.AcquireLockAsync(
            $"{catalogLockName}/{Uri.EscapeDataString(volumeName)}", ct);

        // GC中に未完了のアップロードが存在する場合は、候補の確定・削除を行わない。
        if (await _journalService.HasPendingAsync(volumeName, ct))
            throw new FileServiceException("未完了のジャーナルがあるため、孤児チャンクGCを中止しました。");

        HashSet<string> referenced = await LoadReferencedObjectsAsync(volumeName, header, ct);
        var objectIds = await ListObjectIdsAsync(volumeName, ct);
        var now = DateTimeOffset.UtcNow;
        var ledger = await LoadLedgerAsync(volumeName, ct);

        foreach (string objectId in objectIds)
        {
            if (referenced.Contains(objectId))
                ledger.Remove(objectId);
            else
                ledger.TryAdd(objectId, now);
        }
        foreach (string objectId in ledger.Keys.Where(id => !objectIds.Contains(id, StringComparer.Ordinal)).ToList())
            ledger.Remove(objectId);

        var allCandidates = ledger
            .Where(pair => !referenced.Contains(pair.Key))
            .Select(pair => pair.Key)
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToList();
        var candidates = allCandidates
            .Where(id => now - ledger[id] >= _holdPeriod)
            .ToList();

        if (dryRun)
            return new ChunkGcReport(true, allCandidates.Count, 0, allCandidates, []);

        // 候補確定直前にジャーナルを再確認する。アップロードがGCの最初の
        // チェック後に開始した場合でも、未完了操作の物理チャンクを保持する。
        if (await _journalService.HasPendingAsync(volumeName, ct))
            throw new FileServiceException("GC実行中に未完了のジャーナルが作成されたため、削除を中止しました。");

        // 同じ分散ロックを保持したままカタログを再読込し、公開直後の参照を保護する。
        referenced = await LoadReferencedObjectsAsync(volumeName, header, ct);
        var failed = new List<string>();
        int deleted = 0;
        foreach (string objectId in candidates)
        {
            if (referenced.Contains(objectId))
            {
                ledger.Remove(objectId);
                continue;
            }

            try
            {
                await DeleteWithRetryAsync(volumeName, objectId, ct);
                ledger.Remove(objectId);
                deleted++;
            }
            catch (OperationCanceledException) { throw; }
            catch
            {
                failed.Add(objectId);
            }
        }

        await SaveLedgerAsync(volumeName, ledger, ct);
        return new ChunkGcReport(false, candidates.Count, deleted, candidates, failed);
    }

    private async Task DeleteWithRetryAsync(string volumeName, string objectId, CancellationToken ct)
    {
        Exception? last = null;
        for (int attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                await _chunkStore.DeleteChunksAsync(volumeName, objectId, ct);
                return;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                last = ex;
                if (attempt < 2)
                    await Task.Delay(TimeSpan.FromMilliseconds(100 * (attempt + 1)), ct);
            }
        }
        throw new IOException($"孤児チャンク '{objectId}' の削除に失敗しました。", last);
    }

    private async Task<HashSet<string>> LoadReferencedObjectsAsync(
        string volumeName, VolumeHeader header, CancellationToken ct)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        if (header.IsE2ee)
        {
            byte[]? data = await _storage.ReadAsync($"{volumeName}/catalog-e2ee.json", ct)
                ?? throw new InvalidDataException("E2EE カタログが見つからないため、GCを中止しました。");
            var catalog = JsonSerializer.Deserialize<E2eeCatalog>(data, JsonOptions)
                ?? throw new InvalidDataException("E2EE カタログが不正なため、GCを中止しました。");
            foreach (var entry in catalog.Files.Values)
            {
                for (int i = 0; i < entry.ChunkCount; i++)
                    result.Add(i < entry.ChunkObjectIds.Count && !string.IsNullOrWhiteSpace(entry.ChunkObjectIds[i])
                        ? entry.ChunkObjectIds[i] : entry.FileId);
                if (entry.PendingChunks is not null)
                    foreach (var pending in entry.PendingChunks.Values)
                        result.Add(pending.ObjectId);
            }
        }
        else
        {
            byte[]? data = await _storage.ReadAsync($"{volumeName}/catalog.json", ct)
                ?? throw new InvalidDataException("ファイルカタログが見つからないため、GCを中止しました。");
            var catalog = JsonSerializer.Deserialize<PlainCatalog>(data, JsonOptions)
                ?? throw new InvalidDataException("ファイルカタログが不正なため、GCを中止しました。");
            foreach (var entry in catalog.Files.Values)
            {
                if (entry.ChunkCount > 0)
                    result.Add(entry.ChunkObjectId ?? entry.Name);
            }
        }
        return result;
    }

    private async Task<HashSet<string>> ListObjectIdsAsync(string volumeName, CancellationToken ct)
    {
        string prefix = $"{volumeName}/chunks/";
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (string key in await _storage.ListAsync(prefix, ct))
        {
            if (!key.StartsWith(prefix, StringComparison.Ordinal)) continue;
            string relative = key[prefix.Length..];
            int lastSlash = relative.LastIndexOf('/');
            if (lastSlash <= 0 || lastSlash == relative.Length - 1) continue;
            string index = relative[(lastSlash + 1)..];
            if (index.Length != 5 || !int.TryParse(index, out _)) continue;
            result.Add(relative[..lastSlash]);
        }
        return result;
    }

    private async Task<Dictionary<string, DateTimeOffset>> LoadLedgerAsync(
        string volumeName, CancellationToken ct)
    {
        byte[]? data = await _storage.ReadAsync($"{volumeName}/{CandidateFileName}", ct);
        if (data is null) return new(StringComparer.Ordinal);
        return JsonSerializer.Deserialize<Dictionary<string, DateTimeOffset>>(data, JsonOptions)
            ?? throw new InvalidDataException("GC候補台帳が不正なため、GCを中止しました。");
    }

    private async Task SaveLedgerAsync(
        string volumeName, Dictionary<string, DateTimeOffset> ledger, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        JsonSerializer.Serialize(ms, ledger, JsonOptions);
        ms.Position = 0;
        await _storage.WriteAtomicAsync($"{volumeName}/{CandidateFileName}", ms, ct);
    }

    private sealed class PlainCatalog
    {
        public Dictionary<string, FileMetadata> Files { get; set; } = new(StringComparer.Ordinal);
    }
}
