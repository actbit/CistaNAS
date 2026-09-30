using Android.App;
using Android.Content.PM;
using Avalonia.Android;

namespace CistaNAS.Mobile;

// Avalonia 12 では AppBuilder の構成は CistanasApplication 側で行うため
// MainActivity は AvaloniaMainActivity を継承するだけでよい。
[Activity(
    Label = "CistaNAS",
    Theme = "@style/MyTheme",
    MainLauncher = true,
    // Avalonia's single-view lifetime owns one visual root per process.
    LaunchMode = LaunchMode.SingleTask,
    ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.UiMode)]
public class MainActivity : AvaloniaMainActivity
{
    protected override void OnCreate(Android.OS.Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        Window?.SetFlags(Android.Views.WindowManagerFlags.Secure, Android.Views.WindowManagerFlags.Secure);
    }
}
