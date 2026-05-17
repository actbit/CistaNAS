using CistaNAS.Web.Configuration;
using CistaNAS.Web.Journal;
using CistaNAS.Web.Models;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// ジャーナリングの記録とクラッシュ復旧。Scoped 登録。
/// FileService の書き込み経路から呼ばれる。
/// </summary>
public sealed class JournalService
{
    private readonly string _dataRoot;

    public JournalService(IOptions<CistaNasOptions> options)
    {
        _dataRoot = options.Value.DataRoot;
    }

    /// <summary>ジャーナルにエントリを追記する。書き込み前（pre-commit）に呼ぶ。</summary>
    public void Record(string volumeName, JournalEntry entry)
    {
        string path = GetJournalPath(volumeName);
        entry.Timestamp = DateTimeOffset.UtcNow;
        JournalFile.Append(path, entry);
    }

    /// <summary>書き込み完了後にジャーナルをクリアする（コミット）。</summary>
    public void Commit(string volumeName)
    {
        string path = GetJournalPath(volumeName);
        if (File.Exists(path)) JournalFile.Drain(path);
    }

    /// <summary>
    /// 未コミットのジャーナルがあればエントリを返す（クラッシュ復旧用）。
    /// 復旧後は <see cref="Commit"/> を呼ぶこと。
    /// </summary>
    public IReadOnlyList<JournalEntry> Recover(string volumeName)
    {
        string path = GetJournalPath(volumeName);
        return JournalFile.Read(path);
    }

    /// <summary>ジャーナルが存在するか（未コミットのエントリがあるか）。</summary>
    public bool HasPending(string volumeName)
    {
        string path = GetJournalPath(volumeName);
        if (!File.Exists(path)) return false;
        return JournalFile.Read(path).Count > 0;
    }

    private string GetJournalPath(string volumeName)
        => Path.Combine(_dataRoot, volumeName, "volume" + JournalFile.Suffix);
}
