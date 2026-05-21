using System.Collections.Concurrent;
using System.Text.Json;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Crypto;
using CistaNAS.Web.Journal;
using CistaNAS.Web.Models;
using CistaNAS.Web.Storage;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// マウント済みボリューム内のファイル読み書き・一覧・削除。Scoped 登録。
/// VolumeService（Singleton マウント状態）と JournalService に依存。
/// </summary>
/// <remarks>
/// <para>ボリューム内のファイル管理方式：</para>
/// <para>
/// - volume.dat の暗号化ストリームの末尾にファイルデータを追記
/// - catalog.json（同じディレクトリに平文で保存、アクセス制御で保護）に
///   ファイル名→オフセット/長さのマッピングを保持
/// - ジャーナルで書き込み前後の一貫性を保証
/// </para>
/// </remarks>
public sealed class FileService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private static readonly ConcurrentDictionary<string, object> _catalogLocks = new(StringComparer.Ordinal);

    private readonly VolumeService _volumeService;
    private readonly JournalService _journalService;
    private readonly IStorageProvider _storage;

    public FileService(
        VolumeService volumeService,
        JournalService journalService,
        IStorageProvider storage)
    {
        _volumeService = volumeService;
        _journalService = journalService;
        _storage = storage;
    }

    /// <summary>ボリューム内の全ファイルを一覧。</summary>
    public async Task<ListFilesResponse> ListAsync(string volumeName, CancellationToken ct = default)
    {
        var catalog = await LoadCatalogAsync(volumeName, ct);
        return new ListFilesResponse(catalog.Files.Values.OrderBy(f => f.Name).ToList());
    }

    /// <summary>ファイルをアップロード（新規 or 上書き）。</summary>
    public async Task<FileMetadata> UploadAsync(string volumeName, string fileName, Stream content, long contentLength, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        if (contentLength < 0) throw new ArgumentOutOfRangeException(nameof(contentLength));

        var (stream, _) = _volumeService.GetMounted(volumeName);

        // ジャーナル: 書き込み前
        await _journalService.RecordAsync(volumeName, new JournalEntry
        {
            Operation = JournalOp.WriteFile,
            Path = fileName,
            Length = checked((int)Math.Min(contentLength, int.MaxValue)),
        }, ct);

        // 既存ファイルがあれば上書き（同じオフセットに収まれば再利用、否则追記）
        // ユーザー入力の読み取りは lock 外で行い（非同期 I/O）、書き込みだけ lock 内で実行
        byte[] buffer = new byte[81920];
        long remaining = contentLength;
        using var ms = new MemoryStream(Math.Min((int)Math.Min(contentLength, int.MaxValue), int.MaxValue));
        while (remaining > 0)
        {
            int toRead = (int)Math.Min(buffer.Length, remaining);
            int read = await content.ReadAsync(buffer.AsMemory(0, toRead), ct);
            if (read == 0) break;
            ms.Write(buffer, 0, read);
            remaining -= read;
        }

        // カタログ読み込み + ストリーム書き込み + カタログ保存をボリュームロックで保護
        long offset;
        FileMetadata meta;
        object catLock = _catalogLocks.GetOrAdd(volumeName, _ => new object());
        lock (catLock)
        {
            var catalog = LoadCatalogAsync(volumeName, ct).GetAwaiter().GetResult();
            catalog.Files.TryGetValue(fileName, out var existing);

            lock (stream)
            {
                if (existing is not null && existing.Length >= contentLength)
                {
                    offset = existing.Offset;
                }
                else
                {
                    offset = stream.Length;
                }

                stream.Seek(offset, SeekOrigin.Begin);
                ms.WriteTo(stream);
                stream.Flush();
            }

            meta = new FileMetadata
            {
                Name = fileName,
                Offset = offset,
                Length = contentLength - remaining,
                CreatedAt = existing?.CreatedAt ?? DateTimeOffset.UtcNow,
                ModifiedAt = DateTimeOffset.UtcNow,
            };
            catalog.Files[fileName] = meta;
            SaveCatalogAsync(volumeName, catalog, ct).GetAwaiter().GetResult();
        }

        // ジャーナル: コミット
        await _journalService.CommitAsync(volumeName, ct);

        return meta;
    }

    /// <summary>ファイルをダウンロード。</summary>
    public FileDownloadResponse Download(string volumeName, string fileName)
    {
        var (stream, _) = _volumeService.GetMounted(volumeName);

        object catLock = _catalogLocks.GetOrAdd(volumeName, _ => new object());
        lock (catLock)
        {
            var catalog = LoadCatalogSync(volumeName);
            if (!catalog.Files.TryGetValue(fileName, out var meta))
                throw new FileServiceException($"ファイル '{fileName}' が見つかりません。");

            byte[] data;
            lock (stream)
            {
                stream.Seek(meta.Offset, SeekOrigin.Begin);
                data = new byte[meta.Length];
                int totalRead = 0;
                while (totalRead < data.Length)
                {
                    int n = stream.Read(data, totalRead, data.Length - totalRead);
                    if (n == 0) break;
                    totalRead += n;
                }
            }

            var ms = new MemoryStream(data, 0, data.Length, writable: false);
            return new FileDownloadResponse(ms, meta.Name, meta.Length);
        }
    }

    /// <summary>ファイルを削除。</summary>
    public async Task DeleteAsync(string volumeName, string fileName, CancellationToken ct = default)
    {
        await _journalService.RecordAsync(volumeName, new JournalEntry
        {
            Operation = JournalOp.DeleteFile,
            Path = fileName,
        }, ct);

        object catLock = _catalogLocks.GetOrAdd(volumeName, _ => new object());
        lock (catLock)
        {
            var catalog = LoadCatalogAsync(volumeName, ct).GetAwaiter().GetResult();
            if (!catalog.Files.Remove(fileName))
                throw new FileServiceException($"ファイル '{fileName}' が見つかりません。");

            SaveCatalogAsync(volumeName, catalog, ct).GetAwaiter().GetResult();
        }
        await _journalService.CommitAsync(volumeName, ct);
    }

    /// <summary>クラッシュ復旧：未コミットジャーナルからカタログを修復。</summary>
    public async Task RecoverAsync(string volumeName, CancellationToken ct = default)
    {
        var pending = await _journalService.RecoverAsync(volumeName, ct);
        if (pending.Count == 0) return;

        // 書き込み未完了エントリは無視（次回上書きで回復）
        // 削除済みエントリはカタログから取り除く
        var catalog = await LoadCatalogAsync(volumeName, ct);
        foreach (var entry in pending)
        {
            if (entry.Operation == JournalOp.DeleteFile)
                catalog.Files.Remove(entry.Path);
        }
        await SaveCatalogAsync(volumeName, catalog, ct);
        await _journalService.CommitAsync(volumeName, ct);
    }

    // ---- カタログ ----

    private sealed class FileCatalog
    {
        public Dictionary<string, FileMetadata> Files { get; set; } = new(StringComparer.Ordinal);
    }

    private async Task<FileCatalog> LoadCatalogAsync(string volumeName, CancellationToken ct)
    {
        byte[]? data = await _storage.ReadAsync($"{volumeName}/catalog.json", ct);
        if (data is null) return new FileCatalog();
        return JsonSerializer.Deserialize<FileCatalog>(data, JsonOptions) ?? new FileCatalog();
    }

    private async Task SaveCatalogAsync(string volumeName, FileCatalog catalog, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        JsonSerializer.Serialize(ms, catalog, JsonOptions);
        ms.Position = 0;
        await _storage.WriteAtomicAsync($"{volumeName}/catalog.json", ms, ct);
    }

    // 同期版（Download で使用。後方互換のため残す）
    private FileCatalog LoadCatalogSync(string volumeName)
    {
        byte[]? data = _storage.ReadAsync($"{volumeName}/catalog.json").GetAwaiter().GetResult();
        if (data is null) return new FileCatalog();
        return JsonSerializer.Deserialize<FileCatalog>(data, JsonOptions) ?? new FileCatalog();
    }
}
