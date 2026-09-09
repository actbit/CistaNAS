using System.Text.Json;

namespace CistaNAS.Client.Services;

/// <summary>
/// TOFU public-key pinning の pin（fingerprint）をローカルに永続化する。
/// fingerprint は秘密情報ではないため平文 JSON で保存する（書き換えはマウント時の
/// pin 検証で検知できる。信頼の初期化はユーザーの明示操作のみ）。
/// 保存先: %APPDATA%/CistaNAS/ecdh_pins_{username}.json
/// pin はサーバーに送信しない。
/// </summary>
public static class PublicKeyPinStore
{
    private sealed class PinFile
    {
        public Dictionary<string, string> Pins { get; set; } = new(StringComparer.Ordinal);
    }

    private static readonly string AppDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "CistaNAS");

    private static string GetPath(string username)
    {
        string safe = string.Concat(username.Select(c =>
            char.IsLetterOrDigit(c) || c == '-' || c == '_' ? c : '_'));
        return Path.Combine(AppDir, $"ecdh_pins_{safe}.json");
    }

    private static Dictionary<string, string> LoadAll(string username)
    {
        try
        {
            string path = GetPath(username);
            if (!File.Exists(path)) return new Dictionary<string, string>(StringComparer.Ordinal);
            var file = JsonSerializer.Deserialize<PinFile>(File.ReadAllText(path));
            return file?.Pins is { } pins
                ? new Dictionary<string, string>(pins, StringComparer.Ordinal)
                : new Dictionary<string, string>(StringComparer.Ordinal);
        }
        catch (JsonException)
        {
            // 破損時は pin を初期化（TOFU の初回扱い。不一致アラートは失われるが fail-open より
            // ユーザーが再 pin する方が安全）。サーバー送信される情報はない。
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }
    }

    private static void SaveAll(string username, Dictionary<string, string> pins)
    {
        Directory.CreateDirectory(AppDir);
        string path = GetPath(username);
        string tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(new PinFile { Pins = pins }));
        File.Move(tmp, path, overwrite: true);
    }

    /// <summary>pin を取得する。未 pin なら null。</summary>
    public static string? GetPin(string username, string targetUser)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        return LoadAll(username).TryGetValue(targetUser, out var fp) ? fp : null;
    }

    /// <summary>pin を記録する（TOFU 初回、またはユーザーの明示的な再信頼）。</summary>
    public static void SetPin(string username, string targetUser, string fingerprint)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        var pins = LoadAll(username);
        pins[targetUser] = fingerprint;
        SaveAll(username, pins);
    }
}
