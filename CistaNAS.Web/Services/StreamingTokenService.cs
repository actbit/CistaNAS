using System.Collections.Concurrent;

namespace CistaNAS.Web.Services;

/// <summary>
/// メディアストリーミング用の短命トークン（60秒有効）を管理。
/// ブラウザの video/audio/img は Authorization ヘッダーを送れないため、
/// クエリパラメータで一時的なアクセス権を付与する。
/// </summary>
public sealed class StreamingTokenService
{
    private readonly ConcurrentDictionary<string, StreamingToken> _tokens = new();
    private readonly TimeSpan _ttl = TimeSpan.FromSeconds(60);

    public string Issue(string username, string volumeName, string fileName)
    {
        // 古いトークンを掃除
        Cleanup();

        string token = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        _tokens[token] = new StreamingToken(username, volumeName, fileName, DateTimeOffset.UtcNow + _ttl);
        return token;
    }

    public (string Username, string VolumeName, string FileName)? Validate(string token)
    {
        if (!_tokens.TryRemove(token, out var t)) return null;
        if (t.ExpiresAt < DateTimeOffset.UtcNow) return null;
        return (t.Username, t.VolumeName, t.FileName);
    }

    private void Cleanup()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kvp in _tokens)
        {
            if (kvp.Value.ExpiresAt < now)
                _tokens.TryRemove(kvp.Key, out _);
        }
    }

    private sealed record StreamingToken(string Username, string VolumeName, string FileName, DateTimeOffset ExpiresAt);
}
