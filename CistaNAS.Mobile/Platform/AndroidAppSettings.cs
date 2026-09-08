using Android.Content;
using CistaNAS.Mobile.Core.Abstractions;

namespace CistaNAS.Mobile.Platform;

/// <summary>非機密設定 (サーバー URL・ユーザー名) を SharedPreferences に保存する。</summary>
public sealed class AndroidAppSettings : IAppSettings
{
    private const string PrefsName = "cistanas_settings";

    private static ISharedPreferences Prefs =>
        Application.Context.GetSharedPreferences(PrefsName, FileCreationMode.Private)!;

    public string? ServerUrl
    {
        get => Prefs.GetString("server_url", null);
        set => Apply("server_url", value);
    }

    public string? Username
    {
        get => Prefs.GetString("username", null);
        set => Apply("username", value);
    }

    private static void Apply(string key, string? value)
    {
        using ISharedPreferencesEditor editor = Prefs.Edit()!;
        if (value is null) editor.Remove(key);
        else editor.PutString(key, value);
        editor.Apply();
    }

    public void Save() { /* 各 setter が即時保存するため no-op */ }
}
