using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.Abstractions;

/// <summary>アプリ内でファイルを表示する。内容は永続ストレージへ保存しない。</summary>
public interface IFileViewerLauncher
{
    /// <summary>成功時はcontentの所有権を引き受け、表示終了時にDisposeする。</summary>
    Task<bool> LaunchAsync(ReadOnlyFileContent content);
    void Clear();
}
