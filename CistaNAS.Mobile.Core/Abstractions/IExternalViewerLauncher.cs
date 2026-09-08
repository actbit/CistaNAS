namespace CistaNAS.Mobile.Core.Abstractions;

/// <summary>ファイルを OS の外部アプリ (動画プレーヤー等) で開く。</summary>
public interface IExternalViewerLauncher
{
    /// <summary>
    /// 指定パスのファイルを対応アプリで開く。アプリが無い等で失敗した場合は false。
    /// </summary>
    Task<bool> LaunchAsync(string filePath, string mimeType);
}
