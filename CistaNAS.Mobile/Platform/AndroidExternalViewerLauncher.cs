using Android.Content;
using AndroidX.Core.Content;
using CistaNAS.Mobile.Core.Abstractions;

namespace CistaNAS.Mobile.Platform;

/// <summary>
/// FileProvider 経由で content:// URI を作り ACTION_VIEW で外部アプリに委譲する。
/// (targetSdk 24+ では file:// 直渡しが禁止のため FileProvider が必須。)
/// </summary>
public sealed class AndroidExternalViewerLauncher : IExternalViewerLauncher
{
    public Task<bool> LaunchAsync(string filePath, string mimeType)
    {
        Context context = Application.Context;
        try
        {
            Java.IO.File file = new(filePath);
            if (!file.Exists()) return Task.FromResult(false);

            Android.Net.Uri uri = FileProvider.GetUriForFile(
                context, context.PackageName + ".fileprovider", file)!;

            using var intent = new Intent(Intent.ActionView);
            intent.SetDataAndType(uri, mimeType);
            intent.AddFlags(ActivityFlags.GrantReadUriPermission);
            intent.AddFlags(ActivityFlags.NewTask);

            context.StartActivity(intent);
            return Task.FromResult(true);
        }
        catch (ActivityNotFoundException)
        {
            return Task.FromResult(false);
        }
    }
}
