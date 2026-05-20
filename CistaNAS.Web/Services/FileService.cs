using System.Text.Json;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Crypto;
using CistaNAS.Web.Journal;
using CistaNAS.Web.Models;
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

    private readonly VolumeService _volumeService;
    private readonly JournalService _journalService;
    private readonly string _dataRoot;

    public FileService(
        VolumeService volumeService,
        JournalService journalService,
        IOptions<CistaNasOptions> options)
    {
        _volumeService = volumeService;
        _journalService = journalService;
        _dataRoot = options.Value.DataRoot;
    }

    /// <summary>ボリューム内の全ファイルを一覧。</summary>
    public ListFilesResponse List(string volumeName)
    {
        var catalog = LoadCatalog(volumeName);
        return new ListFilesResponse(catalog.Files.Values.OrderBy(f => f.Name).ToList());
    }

    /// <summary>ファイルをアップロード（新規 or 上書き）。</summary>
    public async Task<FileMetadata> UploadAsync(string volumeName, string fileName, Stream content, long contentLength, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        if (contentLength < 0) throw new ArgumentOutOfRangeException(nameof(contentLength));

        var (stream, _) = _volumeService.GetMounted(volumeName);

        // ジャーナル: 書き込み前
        _journalService.Record(volumeName, new JournalEntry
        {
            Operation = JournalOp.WriteFile,
            Path = fileName,
            Length = (int)contentLength,
        });

        // 既存ファイルがあれば上書き（同じオフセットに収まれば再利用、否则追記）
        var catalog = LoadCatalog(volumeName);
        catalog.Files.TryGetValue(fileName, out var existing);

        long offset;
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
        }

        // ユーザー入力の読み取りは lock 外で行い（非同期 I/O）、書き込みだけ lock 内で実行
        byte[] buffer = new byte[81920];
        long remaining = contentLength;
        using var ms = new MemoryStream((int)contentLength);
        while (remaining > 0)
        {
            int toRead = (int)Math.Min(buffer.Length, remaining);
            int read = await content.ReadAsync(buffer.AsMemory(0, toRead), ct);
            if (read == 0) break;
            ms.Write(buffer, 0, read);
            remaining -= read;
        }

        lock (stream)
        {
            stream.Seek(offset, SeekOrigin.Begin);
            ms.WriteTo(stream);
            stream.Flush();
        }

        // カタログ更新
        var meta = new FileMetadata
        {
            Name = fileName,
            Offset = offset,
            Length = contentLength - remaining, // 実際に書いた分
            CreatedAt = existing?.CreatedAt ?? DateTimeOffset.UtcNow,
            ModifiedAt = DateTimeOffset.UtcNow,
        };
        catalog.Files[fileName] = meta;
        SaveCatalog(volumeName, catalog);

        // ジャーナル: コミット
        _journalService.Commit(volumeName);

        return meta;
    }

    /// <summary>ファイルをダウンロード。</summary>
    public FileDownloadResponse Download(string volumeName, string fileName)
    {
        var catalog = LoadCatalog(volumeName);
        if (!catalog.Files.TryGetValue(fileName, out var meta))
            throw new FileServiceException($"ファイル '{fileName}' が見つかりません。");

        var (stream, _) = _volumeService.GetMounted(volumeName);
        // ロックして安全にシーク→読み取りを行うため、データを独立メモリにコピーして返す
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

    /// <summary>ファイルを削除。</summary>
    public void Delete(string volumeName, string fileName)
    {
        _journalService.Record(volumeName, new JournalEntry
        {
            Operation = JournalOp.DeleteFile,
            Path = fileName,
        });

        var catalog = LoadCatalog(volumeName);
        if (!catalog.Files.Remove(fileName))
            throw new FileServiceException($"ファイル '{fileName}' が見つかりません。");

        SaveCatalog(volumeName, catalog);
        _journalService.Commit(volumeName);
    }

    /// <summary>クラッシュ復旧：未コミットジャーナルからカタログを修復。</summary>
    public void Recover(string volumeName)
    {
        var pending = _journalService.Recover(volumeName);
        if (pending.Count == 0) return;

        // 書き込み未完了エントリは無視（次回上書きで回復）
        // 削除済みエントリはカタログから取り除く
        var catalog = LoadCatalog(volumeName);
        foreach (var entry in pending)
        {
            if (entry.Operation == JournalOp.DeleteFile)
                catalog.Files.Remove(entry.Path);
        }
        SaveCatalog(volumeName, catalog);
        _journalService.Commit(volumeName);
    }

    // ---- カタログ ----

    private sealed class FileCatalog
    {
        public Dictionary<string, FileMetadata> Files { get; set; } = new(StringComparer.Ordinal);
    }

    private FileCatalog LoadCatalog(string volumeName)
    {
        string path = GetCatalogPath(volumeName);
        if (!File.Exists(path)) return new FileCatalog();
        using var fs = File.OpenRead(path);
        return JsonSerializer.Deserialize<FileCatalog>(fs, JsonOptions) ?? new FileCatalog();
    }

    private void SaveCatalog(string volumeName, FileCatalog catalog)
    {
        string path = GetCatalogPath(volumeName);
        string tmp = path + ".tmp";
        using (var fs = File.Create(tmp))
            JsonSerializer.Serialize(fs, catalog, JsonOptions);
        File.Move(tmp, path, overwrite: true);
    }

    private string GetCatalogPath(string volumeName)
        => Path.Combine(_dataRoot, volumeName, "catalog.json");
}
