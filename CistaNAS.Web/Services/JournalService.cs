using System.Text.Json;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Journal;
using CistaNAS.Web.Models;
using CistaNAS.Web.Storage;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// ジャーナリングの記録とクラッシュ復旧。Scoped 登録。
/// FileService の書き込み経路から呼ばれる。
/// </summary>
public sealed class JournalService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    private readonly IStorageProvider _storage;

    public JournalService(IStorageProvider storage)
    {
        _storage = storage;
    }

    /// <summary>ジャーナルにエントリを追記する。書き込み前（pre-commit）に呼ぶ。</summary>
    public async Task RecordAsync(string volumeName, JournalEntry entry, CancellationToken ct = default)
    {
        string journalPath = $"{volumeName}/volume{JournalFile.Suffix}";
        string lockPath = $"{volumeName}/volume{JournalFile.Suffix}.lock";
        entry.Timestamp = DateTimeOffset.UtcNow;

        using (await _storage.AcquireLockAsync(lockPath, ct))
        {
            byte[]? existing = await _storage.ReadAsync(journalPath, ct);
            var journal = existing is not null
                ? JsonSerializer.Deserialize<JournalFile>(existing, JsonOptions) ?? new JournalFile()
                : new JournalFile();
            journal.Pending.Add(entry);

            using var ms = new MemoryStream();
            JsonSerializer.Serialize(ms, journal, JsonOptions);
            ms.Position = 0;
            await _storage.WriteAtomicAsync(journalPath, ms, ct);
        }
    }

    /// <summary>書き込み完了後にジャーナルをクリアする（コミット）。</summary>
    public async Task CommitAsync(string volumeName, CancellationToken ct = default)
    {
        string journalPath = $"{volumeName}/volume{JournalFile.Suffix}";
        string lockPath = $"{volumeName}/volume{JournalFile.Suffix}.lock";

        if (!await _storage.ExistsAsync(journalPath, ct)) return;

        using (await _storage.AcquireLockAsync(lockPath, ct))
        {
            var empty = new JournalFile { Pending = [] };
            using var ms = new MemoryStream();
            JsonSerializer.Serialize(ms, empty, JsonOptions);
            ms.Position = 0;
            await _storage.WriteAtomicAsync(journalPath, ms, ct);
        }
    }

    /// <summary>
    /// 未コミットのジャーナルがあればエントリを返す（クラッシュ復旧用）。
    /// 復旧後は <see cref="CommitAsync"/> を呼ぶこと。
    /// </summary>
    public async Task<IReadOnlyList<JournalEntry>> RecoverAsync(string volumeName, CancellationToken ct = default)
    {
        string journalPath = $"{volumeName}/volume{JournalFile.Suffix}";
        byte[]? data = await _storage.ReadAsync(journalPath, ct);
        if (data is null) return [];
        return JsonSerializer.Deserialize<JournalFile>(data, JsonOptions)?.Pending ?? [];
    }

    /// <summary>ジャーナルが存在するか（未コミットのエントリがあるか）。</summary>
    public async Task<bool> HasPendingAsync(string volumeName, CancellationToken ct = default)
    {
        string journalPath = $"{volumeName}/volume{JournalFile.Suffix}";
        if (!await _storage.ExistsAsync(journalPath, ct)) return false;
        byte[]? data = await _storage.ReadAsync(journalPath, ct);
        if (data is null) return false;
        return (JsonSerializer.Deserialize<JournalFile>(data, JsonOptions)?.Pending.Count ?? 0) > 0;
    }
}
