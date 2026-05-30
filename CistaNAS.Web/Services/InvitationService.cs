using System.Collections.Concurrent;
using System.Security.Cryptography;
using CistaNAS.Web.Volume;

namespace CistaNAS.Web.Services;

/// <summary>
/// 招待URL経由のECDH鍵交換を管理する Singleton Service。
/// 招待データは in-memory で保持（サーバー再起動で消滅）。
/// 期限切れ招待を定期的にクリーンアップする。
/// </summary>
public sealed class InvitationService : BackgroundService
{
    private readonly ConcurrentDictionary<string, InvitationRecord> _invitations = new();

    /// <summary>招待の有効期限。デフォルト 24 時間。</summary>
    private static readonly TimeSpan MaxAge = TimeSpan.FromHours(24);

    /// <summary>クリーンアップ間隔。デフォルト 5 分。</summary>
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);

    public InvitationRecord Create(string inviterUsername, string targetUsername,
        VolumeHeader.UserWrappedKey? groupVolumeWrappedKey = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(inviterUsername);
        ArgumentException.ThrowIfNullOrEmpty(targetUsername);
        if (string.Equals(inviterUsername, targetUsername, StringComparison.Ordinal))
            throw new InvalidOperationException("自分自身を招待することはできません。");

        string id = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var record = new InvitationRecord
        {
            InvitationId = id,
            InviterUsername = inviterUsername,
            TargetUsername = targetUsername,
            CreatedAt = DateTimeOffset.UtcNow,
            GroupVolumeWrappedKey = groupVolumeWrappedKey,
        };
        _invitations[id] = record;
        return record;
    }

    public InvitationRecord? Find(string invitationId)
    {
        _invitations.TryGetValue(invitationId.ToLowerInvariant(), out var record);
        return record;
    }

    /// <summary>招待の受諾データを保存。</summary>
    public void SetAcceptedData(string invitationId, string encryptedPublicKey, string nonce)
    {
        ArgumentException.ThrowIfNullOrEmpty(invitationId);
        ArgumentException.ThrowIfNullOrEmpty(encryptedPublicKey);
        ArgumentException.ThrowIfNullOrEmpty(nonce);
        if (!_invitations.TryGetValue(invitationId.ToLowerInvariant(), out var record))
            throw new InvalidOperationException("招待が見つかりません。");
        record.EncryptedPublicKey = encryptedPublicKey;
        record.Nonce = nonce;
        record.AcceptedAt = DateTimeOffset.UtcNow;
    }

    /// <summary>招待を削除（受諾完了後）。</summary>
    public void Remove(string invitationId) => _invitations.TryRemove(invitationId.ToLowerInvariant(), out _);

    /// <summary>期限切れ招待を一括削除。</summary>
    public void Cleanup(TimeSpan maxAge)
    {
        var cutoff = DateTimeOffset.UtcNow - maxAge;
        foreach (var kvp in _invitations.ToList())
        {
            if (kvp.Value.CreatedAt < cutoff)
                _invitations.TryRemove(kvp.Key, out _);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(CleanupInterval, stoppingToken);
            Cleanup(MaxAge);
        }
    }
}

public sealed class InvitationRecord
{
    public required string InvitationId { get; set; }
    public required string InviterUsername { get; set; }
    public required string TargetUsername { get; set; }
    public required DateTimeOffset CreatedAt { get; set; }

    /// <summary>招待秘密鍵由来の鍵で暗号化された対象ユーザーの公開鍵。</summary>
    public string? EncryptedPublicKey { get; set; }

    /// <summary>暗号化時の nonce。</summary>
    public string? Nonce { get; set; }

    public DateTimeOffset? AcceptedAt { get; set; }

    /// <summary>セキュアモードのグループボリューム鍵（招待秘密鍵で暗号化済み）。</summary>
    public VolumeHeader.UserWrappedKey? GroupVolumeWrappedKey { get; set; }
}
