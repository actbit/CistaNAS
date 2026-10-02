using System.Runtime.InteropServices;
using System.Text.Json;

namespace CistaNAS.Web.Journal;

/// <summary>ジャーナルエントリの種類。</summary>
public enum JournalOp
{
    WriteFile,
    DeleteFile,
    Truncate,
}

/// <summary>単一のジャーナルエントリ。</summary>
public sealed class JournalEntry
{
    public long Id { get; set; }
    /// <summary>操作ごとに一意な ID。RecordAsync で自動設定される。</summary>
    public string? OperationId { get; set; }
    public JournalOp Operation { get; set; }
    public string Path { get; set; } = "";
    public long Offset { get; set; }
    public int Length { get; set; }
    public DateTimeOffset Timestamp { get; set; }
}

/// <summary>ジャーナルファイルのヘッダ。</summary>
public sealed class JournalFile
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    public const string Suffix = ".journal";

    public string VolumeName { get; set; } = "";
    [System.Text.Json.Serialization.JsonRequired]
    public List<JournalEntry> Pending { get; set; } = [];

    internal static JournalFile Deserialize(ReadOnlySpan<byte> data)
    {
        try { return Validate(JsonSerializer.Deserialize<JournalFile>(data, JsonOptions)); }
        catch (JsonException ex) { throw new InvalidDataException("ジャーナルの保存内容が不正です。復旧元を確認してください。", ex); }
    }

    private static JournalFile Deserialize(Stream data)
    {
        try { return Validate(JsonSerializer.Deserialize<JournalFile>(data, JsonOptions)); }
        catch (JsonException ex) { throw new InvalidDataException("ジャーナルの保存内容が不正です。復旧元を確認してください。", ex); }
    }

    private static JournalFile Validate(JournalFile? journal)
    {
        if (journal?.Pending is null || journal.Pending.Any(entry => entry is null || !Enum.IsDefined(entry.Operation)))
            throw new InvalidDataException("ジャーナルの保存内容が不正です。復旧元を確認してください。");
        return journal;
    }

    /// <summary>ジャーナルの追記。完了後に <see cref="Flush"/> を呼ぶこと。</summary>
    public static void Append(string journalPath, JournalEntry entry)
    {
        using var lockStream = File.Open(
            journalPath + ".lock",
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None);
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            lockStream.Lock(0, 1);

        JournalFile journal;
        if (File.Exists(journalPath))
        {
            using var fs = File.OpenRead(journalPath);
            journal = Deserialize(fs);
        }
        else
        {
            journal = new JournalFile();
        }

        journal.Pending.Add(entry);

        string tmp = journalPath + ".tmp";
        using (var fs = File.Create(tmp))
            JsonSerializer.Serialize(fs, journal, JsonOptions);
        File.Move(tmp, journalPath, overwrite: true);
    }

    /// <summary>ジャーナルを読み込み、ファイルをクリアする（アトミック）。</summary>
    public static List<JournalEntry> Drain(string journalPath)
    {
        if (!File.Exists(journalPath)) return [];

        using var lockStream = File.Open(
            journalPath + ".lock",
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None);
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            lockStream.Lock(0, 1);

        List<JournalEntry> entries;
        using (var fs = File.OpenRead(journalPath))
        {
            var journal = Deserialize(fs);
            entries = journal.Pending;
        }

        // ジャーナルを空に（=コミット）
        string tmp = journalPath + ".tmp";
        var empty = new JournalFile { Pending = [] };
        using (var tfs = File.Create(tmp))
            JsonSerializer.Serialize(tfs, empty, JsonOptions);
        File.Move(tmp, journalPath, overwrite: true);

        return entries;
    }

    /// <summary>ジャーナルが存在すれば内容を返す（クリアしない）。</summary>
    public static List<JournalEntry> Read(string journalPath)
    {
        if (!File.Exists(journalPath)) return [];
        using var fs = File.OpenRead(journalPath);
        return Deserialize(fs).Pending;
    }
}
