using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Crypto;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// ユーザアカウントの永続化（users.json）。Singleton。
/// パスワード変更時は VolumeService.RewrapAllForUser を呼んで KEK を再ラップする。
/// </summary>
public sealed class UserStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _path;
    private readonly int _pbkdf2Iterations;
    private readonly IServiceProvider _services;
    private readonly object _gate = new();
    private List<UserAccount> _users;

    public UserStore(IOptions<CistaNasOptions> options, ILogger<UserStore> logger, IServiceProvider services)
    {
        _services = services;
        var o = options.Value;
        _pbkdf2Iterations = o.Auth.Pbkdf2Iterations;
        Directory.CreateDirectory(o.DataRoot);
        _path = Path.Combine(o.DataRoot, "users.json");
        _users = Load();
    }

    /// <summary>ユーザーが1人でも存在するか（セットアップウィザードの表示判定）。</summary>
    public bool HasAnyUsers
    {
        get { lock (_gate) { return _users.Count > 0; } }
    }

    public UserAccount? Find(string username)
    {
        lock (_gate)
        {
            return _users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.Ordinal));
        }
    }

    public IReadOnlyList<UserAccount> ListUsers()
    {
        lock (_gate) { return _users.ToList(); }
    }

    public void CreateUser(string username, string password, string role = "user")
    {
        lock (_gate)
        {
            if (_users.Any(u => string.Equals(u.Username, username, StringComparison.Ordinal)))
                throw new InvalidOperationException($"ユーザー '{username}' は既に存在します。");
            ArgumentException.ThrowIfNullOrEmpty(username);
            ArgumentException.ThrowIfNullOrEmpty(password);

            _users.Add(new UserAccount
            {
                Username = username,
                PasswordHash = PasswordHasher.Hash(password, _pbkdf2Iterations),
                Role = role,
            });
            Save();
        }
    }

    public void DeleteUser(string username)
    {
        lock (_gate)
        {
            var user = _users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.Ordinal));
            if (user is null)
                throw new InvalidOperationException($"ユーザー '{username}' が見つかりません。");

            _users.Remove(user);
            Save();
        }
    }

    public void UpdateRole(string username, string newRole)
    {
        lock (_gate)
        {
            var user = _users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.Ordinal));
            if (user is null)
                throw new InvalidOperationException($"ユーザー '{username}' が見つかりません。");

            user.Role = newRole;
            Save();
        }
    }

    public bool IsAdmin(string username)
    {
        lock (_gate)
        {
            return _users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.Ordinal))?.Role == "admin";
        }
    }

    /// <summary>セットアップウィザードから初期管理者を作成。</summary>
    public void CreateInitialAdmin(string username, string password)
    {
        lock (_gate)
        {
            if (_users.Count > 0)
                throw new InvalidOperationException("ユーザーが既に存在します。");

            _users.Add(new UserAccount
            {
                Username = username,
                PasswordHash = PasswordHasher.Hash(password, _pbkdf2Iterations),
                Role = "admin",
            });
            Save();
        }
    }

    /// <summary>
    /// パスワードを変更する。KEK 再ラップを先に行い、成功後にハッシュを更新。
    /// </summary>
    public bool ChangePassword(string username, string oldPassword, string newPassword)
    {
        lock (_gate)
        {
            var user = _users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.Ordinal));
            if (user is null) return false;

            if (!PasswordHasher.Verify(oldPassword, user.PasswordHash))
                return false;

            // 先に全ボリュームの KEK を再ラップ
            var volumeService = _services.GetRequiredService<VolumeService>();
            volumeService.RewrapAllForUser(username, oldPassword, newPassword);

            // 成功後にハッシュ更新
            user.PasswordHash = PasswordHasher.Hash(newPassword, _pbkdf2Iterations);
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
        catch (JsonException) { return []; }
    }

    private void Save()
    {
        string tmp = _path + ".tmp";
        using (var fs = File.Create(tmp))
            JsonSerializer.Serialize(fs, _users, JsonOptions);
        File.Move(tmp, _path, overwrite: true);
    }
}
