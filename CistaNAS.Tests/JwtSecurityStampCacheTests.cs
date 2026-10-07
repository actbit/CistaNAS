using CistaNAS.Web.Services;
using Microsoft.Extensions.Caching.Memory;

namespace CistaNAS.Tests;

public sealed class JwtSecurityStampCacheTests
{
    [Fact]
    public void Invalidate_ImmediatelyRejectsTheOldStamp()
    {
        using var memory = new MemoryCache(new MemoryCacheOptions());
        var cache = new JwtSecurityStampCache(memory);

        cache.Set("alice", "before", TimeSpan.FromMinutes(5));
        Assert.True(cache.Matches("alice", "before"));

        cache.Invalidate("alice");

        Assert.False(cache.Matches("alice", "before"));
    }
}
