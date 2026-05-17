using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Crypto;
using CistaNAS.Web.Models;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// ユーザアカウントの永続化（users.json）。共有状態を持つため Singleton 登録。
/// 初回起動時に初期管理者をシードする。AuthService から呼ばれる。
/// </summary>
public sealed class UserStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _path;
    private readonly object _gate = new();
    private List<UserAccount> _users;

    public UserStore(IOptions<CistaNasOptions> options, ILogger<UserStore> logger)
    {
        var o = options.Value;
        Directory.CreateDirectory(o.DataRoot);
        _path = Path.Combine(o.DataRoot, "users.json");
        _users = Load();

        if (_users.Count == 0)
        {
            bool generated = string.IsNullOrEmpty(o.Auth.DefaultAdminPassword);
            string password = generated
                ? Convert.ToBase64String(RandomNumberGenerator.GetBytes(12))
                : o.Auth.DefaultAdminPassword!;

            _users.Add(new UserAccount
            {
                Username = o.Auth.DefaultAdminUser,
                PasswordHash = PasswordHasher.Hash(password, o.Auth.Pbkdf2Iterations),
                Role = "admin",
            });
            Save();

            if (generated)
            {
                logger.LogWarning(
                    "初期管理者を作成しました。ユーザ: {User} / 自動生成パスワード: {Password}（初回ログイン後に変更してください）",
                    o.Auth.DefaultAdminUser, password);
            }
            else
            {
                logger.LogInformation("初期管理者を作成しました。ユーザ: {User}（設定のパスワード）", o.Auth.DefaultAdminUser);
            }
        }
    }

    public UserAccount? Find(string username)
    {
        lock (_gate)
        {
            return _users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.Ordinal));
        }
    }

    /// <summary>パスワードを変更する。対象ユーザが無ければ false。</summary>
    public bool ChangePassword(string username, string newPasswordHash)
    {
        lock (_gate)
        {
            var user = _users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.Ordinal));
            if (user is null) return false;
            user.PasswordHash = newPasswordHash;
            Save();
            return true;
        }
    }

    private List<UserAccount> Load()
    {
        if (!File.Exists(_path)) return [];
        try
        {
            using var fs = File.OpenRead(_path);
            return JsonSerializer.Deserialize<List<UserAccount>>(fs, JsonOptions) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private void Save()
    {
        // 一時ファイル経由でアトミックに置換
        string tmp = _path + ".tmp";
        using (var fs = File.Create(tmp))
        {
            JsonSerializer.Serialize(fs, _users, JsonOptions);
        }
        File.Move(tmp, _path, overwrite: true);
    }
}
