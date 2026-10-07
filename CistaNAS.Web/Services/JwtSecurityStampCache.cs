using Microsoft.Extensions.Caching.Memory;

namespace CistaNAS.Web.Services;

/// <summary>
/// JWT の SecurityStamp 検証結果を短時間だけキャッシュする。
/// パスワード・ロール変更・ユーザー削除時には明示的に削除し、失効遅延を発生させない。
/// </summary>
public sealed class JwtSecurityStampCache(IMemoryCache cache)
{
    private const string Prefix = "secst:";

    private static string Key(string username) => Prefix + username;

    public bool Matches(string username, string stamp)
        => cache.TryGetValue(Key(username), out string? cached)
            && string.Equals(cached, stamp, StringComparison.Ordinal);

    public void Set(string username, string stamp, TimeSpan lifetime)
        => cache.Set(Key(username), stamp, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = lifetime,
        });

    public void Invalidate(string username)
        => cache.Remove(Key(username));
}
