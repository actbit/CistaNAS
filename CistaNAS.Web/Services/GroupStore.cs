using System.Text.Json;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Storage;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

public sealed class GroupStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly IStorageProvider _storage;
    private readonly IServiceProvider _services;
    private readonly object _gate = new();
    private List<GroupAccount> _groups;

    public GroupStore(IStorageProvider storage, IOptions<CistaNasOptions> options, IServiceProvider services)
    {
        _storage = storage;
        _services = services;
        _groups = LoadAsync().GetAwaiter().GetResult();
    }

    public IReadOnlyList<GroupAccount> ListGroups()
    {
        lock (_gate) { return _groups.ToList(); }
    }

    public GroupAccount? Find(string groupName)
    {
        lock (_gate)
        {
            return _groups.FirstOrDefault(g =>
                string.Equals(g.GroupName, groupName, StringComparison.Ordinal));
        }
    }

    public List<GroupAccount> GetGroupsForUser(string username)
    {
        lock (_gate)
        {
            return _groups
                .Where(g => g.Members.Contains(username))
                .ToList();
        }
    }

    public bool IsMember(string groupName, string username)
    {
        lock (_gate)
        {
            return _groups.Any(g =>
                string.Equals(g.GroupName, groupName, StringComparison.Ordinal) &&
                g.Members.Contains(username));
        }
    }

    public void CreateGroup(string groupName, string ownerUser)
    {
        ArgumentException.ThrowIfNullOrEmpty(groupName);
        ArgumentException.ThrowIfNullOrEmpty(ownerUser);

        lock (_gate)
        {
            if (_groups.Any(g => string.Equals(g.GroupName, groupName, StringComparison.Ordinal)))
                throw new InvalidOperationException($"グループ '{groupName}' は既に存在します。");

            _groups.Add(new GroupAccount
            {
                GroupName = groupName,
                OwnerUser = ownerUser,
                Members = [ownerUser],
                CreatedAt = DateTimeOffset.UtcNow,
            });
            SaveAsync().GetAwaiter().GetResult();
        }
    }

    public void DeleteGroup(string groupName, string requester)
    {
        lock (_gate)
        {
            var group = _groups.FirstOrDefault(g =>
                string.Equals(g.GroupName, groupName, StringComparison.Ordinal));
            if (group is null)
                throw new InvalidOperationException($"グループ '{groupName}' が見つかりません。");
            if (group.OwnerUser != requester)
                throw new InvalidOperationException("オーナーのみがグループを削除できます。");

            _groups.Remove(group);
            SaveAsync().GetAwaiter().GetResult();
        }

        // ボリュームからグループ参照を除去（ロックの外で）
        try
        {
            var vs = _services.GetRequiredService<VolumeService>();
            vs.RemoveGroupFromAllVolumes(groupName);
        }
        catch { }
    }

    public void AddMember(string groupName, string requester, string username)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        lock (_gate)
        {
            var group = FindInternal(groupName);
            if (group.OwnerUser != requester)
                throw new InvalidOperationException("オーナーのみがメンバーを追加できます。");
            if (!group.Members.Add(username))
                throw new InvalidOperationException($"ユーザー '{username}' は既にメンバーです。");
            SaveAsync().GetAwaiter().GetResult();
        }
    }

    public void RemoveMember(string groupName, string requester, string username)
    {
        lock (_gate)
        {
            var group = FindInternal(groupName);
            if (group.OwnerUser != requester)
                throw new InvalidOperationException("オーナーのみがメンバーを削除できます。");
            if (username == group.OwnerUser)
                throw new InvalidOperationException("オーナーは削除できません。");
            if (!group.Members.Remove(username))
                throw new InvalidOperationException($"ユーザー '{username}' はメンバーではありません。");
            SaveAsync().GetAwaiter().GetResult();
        }
    }

    public void RemoveUserFromAllGroups(string username)
    {
        lock (_gate)
        {
            bool changed = false;
            foreach (var g in _groups)
                changed |= g.Members.Remove(username);
            if (changed) SaveAsync().GetAwaiter().GetResult();
        }
    }

    private GroupAccount FindInternal(string groupName)
    {
        return _groups.FirstOrDefault(g =>
            string.Equals(g.GroupName, groupName, StringComparison.Ordinal))
            ?? throw new InvalidOperationException($"グループ '{groupName}' が見つかりません。");
    }

    private async Task<List<GroupAccount>> LoadAsync()
    {
        byte[]? data = await _storage.ReadAsync("groups.json");
        if (data is null) return [];
        try
        {
            return JsonSerializer.Deserialize<List<GroupAccount>>(data, JsonOptions) ?? [];
        }
        catch (JsonException) { return []; }
    }

    private async Task SaveAsync()
    {
        using var ms = new MemoryStream();
        JsonSerializer.Serialize(ms, _groups, JsonOptions);
        ms.Position = 0;
        await _storage.WriteAtomicAsync("groups.json", ms);
    }
}
