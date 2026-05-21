using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Crypto;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// ユーザアカウントの永続化（users.json）。Singleton。
/// パスワード変更時は VolumeService.RewrapAllForUser を呼んで KEK を再ラップする。
/// </summary>
public sealed class UserStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly IStorageProvider _storage;
    private readonly int _pbkdf2Iterations;
    private readonly IServiceProvider _services;
    private readonly object _gate = new();
    private List<UserAccount> _users;

    public UserStore(IStorageProvider storage, IOptions<CistaNasOptions> options, ILogger<UserStore> logger, IServiceProvider services)
    {
        _storage = storage;
        _services = services;
        var o = options.Value;
        _pbkdf2Iterations = o.Auth.Pbkdf2Iterations;
        _users = LoadAsync().GetAwaiter().GetResult();
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
            SaveAsync().GetAwaiter().GetResult();
        }

        // ホームボリューム自動作成（ロック外で実行）
        try
        {
            var volumeService = _services.GetRequiredService<VolumeService>();
            string homeName = $"home__{username}";
            volumeService.CreateInternal(homeName, username, password: null, encrypted: false);
        }
        catch { /* 既に存在する等は無視 */ }
    }

    public void DeleteUser(string username)
    {
        lock (_gate)
        {
            var user = _users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.Ordinal));
            if (user is null)
                throw new InvalidOperationException($"ユーザー '{username}' が見つかりません。");

            _users.Remove(user);
            SaveAsync().GetAwaiter().GetResult();
        }

        // グループから除去 + ホームボリューム削除
        try
        {
            var groupStore = _services.GetRequiredService<GroupStore>();
            groupStore.RemoveUserFromAllGroups(username);
        }
        catch { }

        try
        {
            var volumeService = _services.GetRequiredService<VolumeService>();
            volumeService.DeleteVolume($"home__{username}");
        }
        catch { }
    }

    public void UpdateRole(string username, string newRole)
    {
        lock (_gate)
        {
            var user = _users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.Ordinal));
            if (user is null)
                throw new InvalidOperationException($"ユーザー '{username}' が見つかりません。");

            user.Role = newRole;
            SaveAsync().GetAwaiter().GetResult();
        }
    }

    public bool IsAdmin(string username)
    {
        lock (_gate)
        {
            return _users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.Ordinal))?.Role == "admin";
        }
    }

    public string? GetPublicKey(string username)
    {
        lock (_gate)
        {
            return _users.FirstOrDefault(u =>
                string.Equals(u.Username, username, StringComparison.Ordinal))?.PublicKey;
        }
    }

    public void UpdatePublicKey(string username, string publicKeyBase64)
    {
        lock (_gate)
        {
            var user = _users.FirstOrDefault(u =>
                string.Equals(u.Username, username, StringComparison.Ordinal))
                ?? throw new InvalidOperationException($"ユーザー '{username}' が見つかりません。");
            user.PublicKey = publicKeyBase64;
            SaveAsync().GetAwaiter().GetResult();
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
            SaveAsync().GetAwaiter().GetResult();
        }
    }

    /// <summary>
    /// パスワードを変更する。KEK 再ラップを先に行い、成功後にハッシュを更新。
    /// </summary>
    public bool ChangePassword(string username, string oldPassword, string newPassword)
    {
        // 1) ロック内で旧パスワード検証 + ユーザー存在確認
        UserAccount? user;
        lock (_gate)
        {
            user = _users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.Ordinal));
            if (user is null) return false;

            if (!PasswordHasher.Verify(oldPassword, user.PasswordHash))
                return false;
        }

        // 2) ロック外で重い KEK 再ラップを実行（他操作をブロックしない）
        var volumeService = _services.GetRequiredService<VolumeService>();
        volumeService.RewrapAllForUser(username, oldPassword, newPassword);

        // 3) 再ラップ成功後にハッシュ更新
        lock (_gate)
        {
            user.PasswordHash = PasswordHasher.Hash(newPassword, _pbkdf2Iterations);
            SaveAsync().GetAwaiter().GetResult();
            return true;
        }
    }

    private async Task<List<UserAccount>> LoadAsync()
    {
        byte[]? data = await _storage.ReadAsync("users.json");
        if (data is null) return [];
        try
        {
            return JsonSerializer.Deserialize<List<UserAccount>>(data, JsonOptions) ?? [];
        }
        catch (JsonException) { return []; }
    }

    private async Task SaveAsync()
    {
        using var ms = new MemoryStream();
        JsonSerializer.Serialize(ms, _users, JsonOptions);
        ms.Position = 0;
        await _storage.WriteAtomicAsync("users.json", ms);
    }
}
