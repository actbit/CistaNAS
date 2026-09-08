using Android.App;
using Android.Runtime;
using Avalonia;
using Avalonia.Android;

namespace CistaNAS.Mobile;

/// <summary>
/// Avalonia 12 の Android 起動エントリ。
/// AvaloniaAndroidApplication&lt;TApp&gt; が OnCreate 内で AppBuilder を構築し
/// ApplicationLifetime (ISingleViewApplicationLifetime) 経由で起動する。
/// </summary>
[Application]
public class CistanasApplication : AvaloniaAndroidApplication<App>
{
    public CistanasApplication(IntPtr javaReference, JniHandleOwnership transfer)
        : base(javaReference, transfer)
    {
    }

    protected override AppBuilder CustomizeAppBuilder(AppBuilder builder)
    {
        return base.CustomizeAppBuilder(builder);
    }
}
