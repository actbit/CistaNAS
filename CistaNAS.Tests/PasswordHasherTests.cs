using CistaNAS.Web.Crypto;

namespace CistaNAS.Tests;

/// <summary>
/// PasswordHasher の単体テスト。
/// 巨大反復数による CPU DoS 防止（上限検証）と、正常系ラウンドトリップを検証。
/// </summary>
public class PasswordHasherTests
{
    [Fact]
    public void Hash_Verify_Roundtrip()
    {
        string hash = PasswordHasher.Hash("password", 1000);
        Assert.True(PasswordHasher.Verify("password", hash));
        Assert.False(PasswordHasher.Verify("wrong", hash));
    }

    /// <summary>改ざんされた巨大反復数で CPU DoS を起こさず即座に false を返すこと。</summary>
    [Fact]
    public void Verify_HugeIterations_ReturnsFalse_DoSProtection()
    {
        string encoded = $"pbkdf2-sha256${int.MaxValue}${Convert.ToBase64String(new byte[16])}${Convert.ToBase64String(new byte[32])}";
        Assert.False(PasswordHasher.Verify("password", encoded));
    }

    /// <summary>Hash 側でも上限超の反復数を拒否すること（Verify との上限不一致でログイン不能になるのを防ぐ）。</summary>
    [Fact]
    public void Hash_TooManyIterations_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => PasswordHasher.Hash("pw", 10_000_001));
    }

    [Fact]
    public void Verify_Malformed_ReturnsFalse()
    {
        Assert.False(PasswordHasher.Verify("password", "garbage"));
        Assert.False(PasswordHasher.Verify("password", "pbkdf2-sha256$abc$salt$hash"));
        Assert.False(PasswordHasher.Verify("", "pbkdf2-sha256$1$s$h"));
    }
}
