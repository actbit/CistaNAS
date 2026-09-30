using Android.Content;
using Android.OS;
using CistaNAS.Mobile.Core.Abstractions;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Platform;

/// <summary>同じアプリ内の表示画面だけを起動する。URIや復号ファイルを外部へ渡さない。</summary>
public sealed class AndroidFileViewerLauncher : IFileViewerLauncher
{
    internal static StreamingFileRegistry Files { get; } = new();

    public Task<bool> LaunchAsync(ReadOnlyFileContent content)
    {
        bool media = content.MimeType.StartsWith("video/", StringComparison.Ordinal)
            || content.MimeType.StartsWith("audio/", StringComparison.Ordinal);
        if (!media && content.MimeType != "application/pdf") return Task.FromResult(false);
        if (content.MimeType == "application/pdf" && !OperatingSystem.IsAndroidVersionAtLeast(26))
            throw new NotSupportedException("PDFのアプリ内表示にはAndroid 8以降が必要です。");
        string id = Files.Add(content);
        try
        {
            using var intent = new Intent(Android.App.Application.Context, typeof(StreamingViewerActivity));
            intent.PutExtra("content-id", id);
            intent.AddFlags(ActivityFlags.NewTask);
            Android.App.Application.Context.StartActivity(intent);
            return Task.FromResult(true);
        }
        catch
        {
            Files.Remove(id);
            throw;
        }
    }

    public void Clear() => Files.Clear();
}
