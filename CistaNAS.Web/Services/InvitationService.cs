using System.Collections.Concurrent;
using System.Security.Cryptography;
using CistaNAS.Web.Volume;

namespace CistaNAS.Web.Services;

/// <summary>
/// 招待URL経由のECDH鍵交換を管理する Singleton Service。
/// 招待データは in-memory で保持（サーバー再起動で消滅）。
/// </summary>
public sealed class InvitationService
{
    private readonly ConcurrentDictionary<string, InvitationRecord> _invitations = new();

    public InvitationRecord Create(string inviterUsername, string targetUsername,
        VolumeHeader.UserWrappedKey? groupVolumeWrappedKey = null)
    {
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
        foreach (var kvp in _invitations)
        {
            if (kvp.Value.CreatedAt < cutoff)
                _invitations.TryRemove(kvp.Key, out _);
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
