using CistaNAS.Shared.Crypto;
using Xunit;

namespace CistaNAS.Tests;

/// <summary>
/// Argon2id (RFC 9106) プリミティブのテスト。
/// RFC 9106 §5.3 の公式テストベクトルと、hash-wasm (ブラウザ側実装) との相互運性を検証する。
/// </summary>
public class Argon2idKdfTests
{
    /// <summary>RFC 9106 §5.3 Argon2id テストベクトル（32 バイト出力）。</summary>
    [Fact]
    public void Derive_MatchesRfc9106TestVector()
    {
        byte[] password = Enumerable.Repeat((byte)0x01, 32).ToArray();
        byte[] salt = Enumerable.Repeat((byte)0x02, 16).ToArray();
        byte[] secret = Enumerable.Repeat((byte)0x03, 8).ToArray();
        byte[] ad = Enumerable.Repeat((byte)0x04, 12).ToArray();

        byte[] tag = Argon2idKdf.Derive(
            password, salt, timeCost: 3, memoryKiB: 32, parallelism: 4,
            length: 32, secret: secret, associatedData: ad);

        // RFC 9106 Section 5.3 の Tag
        Assert.Equal(
            "0D640DF58D78766C08C037A34A8B53C9D01EF0452D75B65EB52520E96B01E659",
            Convert.ToHexString(tag));
    }

    /// <summary>
    /// hash-wasm 4.12.0 (ブラウザ側 Argon2id) との相互運性確認。
    /// 同一入力 → 同一ダイジェスト。node (hash-wasm) で計算した値:
    ///   argon2id({password:'cista-test-password', salt:'0123456789abcdef',
    ///             iterations:3, parallelism:4, memorySize:1024, hashLength:32})
    /// </summary>
    [Fact]
    public void Derive_MatchesHashWasmDigest()
    {
        byte[] tag = Argon2idKdf.Derive(
            "cista-test-password", "0123456789abcdef"u8.ToArray(),
            timeCost: 3, memoryKiB: 1024, parallelism: 4, length: 32);

        Assert.Equal(
            "72CC3C67C6D9FDCA114319CC76845EA9CE500A8465AB8C52D2D2926FD182BB46",
            Convert.ToHexString(tag));
    }

    [Fact]
    public void Derive_IsDeterministic()
    {
        byte[] salt = Enumerable.Repeat((byte)0x0A, 16).ToArray();
        byte[] a = Argon2idKdf.Derive("pw", salt, 1, 1024, 1, 32);
        byte[] b = Argon2idKdf.Derive("pw", salt, 1, 1024, 1, 32);
        Assert.Equal(a, b);
    }

    [Fact]
    public void Derive_DifferentPasswordOrSaltOrParams_ProducesDifferentKeys()
    {
        byte[] salt = Enumerable.Repeat((byte)0x0B, 16).ToArray();
        byte[] baseKey = Argon2idKdf.Derive("pw", salt, 1, 1024, 1, 32);

        Assert.NotEqual(baseKey, Argon2idKdf.Derive("pw2", salt, 1, 1024, 1, 32));
        Assert.NotEqual(baseKey, Argon2idKdf.Derive("pw", Enumerable.Repeat((byte)0x0C, 16).ToArray(), 1, 1024, 1, 32));
        Assert.NotEqual(baseKey, Argon2idKdf.Derive("pw", salt, 2, 1024, 1, 32));
        Assert.NotEqual(baseKey, Argon2idKdf.Derive("pw", salt, 1, 2048, 1, 32));
        Assert.NotEqual(baseKey, Argon2idKdf.Derive("pw", salt, 1, 1024, 2, 32));
    }

    [Theory]
    [InlineData(0, 1024, 1)]   // t=0
    [InlineData(1, 1024, 0)]   // p=0
    [InlineData(1, 8, 2)]      // m < 8*p
    [InlineData(1, 7, 1)]      // m < 8
    public void Derive_InvalidParams_Throws(int t, int m, int p)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2idKdf.Derive("pw", Enumerable.Repeat((byte)0x0D, 16).ToArray(), t, m, p, 32));
    }

    [Theory]
    [InlineData(1_000_001, 65536, 4, false)]  // t 上限超
    [InlineData(4, 1_048_577, 4, false)]      // m 上限超（1 GiB）
    [InlineData(4, 65536, 65, false)]         // p 上限超
    [InlineData(4, 65536, 4, true)]
    [InlineData(1, 8, 1, true)]               // 仕様最小
    public void IsWithinVerifyLimits_ChecksBounds(int t, int m, int p, bool expected)
    {
        Assert.Equal(expected, Argon2idKdf.IsWithinVerifyLimits(t, m, p));
    }

    [Fact]
    public void KdfSpec_DefaultArgon2id_IsValid()
    {
        Assert.True(KdfSpec.DefaultArgon2id.IsValidArgon2id());
        Assert.True(KdfSpec.DefaultArgon2id.IsArgon2id);
        Assert.False(KdfSpec.DefaultArgon2id.IsPbkdf2);
    }

    [Fact]
    public void DeriveKek_Argon2id_CompositeMatchesStages()
    {
        // 合成 KDF: KEK = PBKDF2-SHA256(Argon2id(pw, combinedSalt, t, m, p), combinedSalt, Iterations, 32)
        byte[] salt = Enumerable.Repeat((byte)0x21, 16).ToArray();
        byte[] combined = KeyDerivation.CombineUserSalt("alice", salt);
        byte[] argon = Argon2idKdf.Derive("pw", combined, timeCost: 4, memoryKiB: 1024, parallelism: 1, length: 32);
        byte[] expected = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(
            argon, combined, 1000, System.Security.Cryptography.HashAlgorithmName.SHA256, 32);
        byte[] actual = KeyDerivation.DeriveKek("alice", "pw", salt, new KdfSpec(KdfSpec.Argon2id, 1000, 1024, 1));
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void DeriveKek_DifferentUser_ProducesDifferentKek()
    {
        byte[] salt = Enumerable.Repeat((byte)0x22, 16).ToArray();
        byte[] alice = KeyDerivation.DeriveKek("alice", "pw", salt, new KdfSpec(KdfSpec.Argon2id, 1000, 1024, 1));
        byte[] bob = KeyDerivation.DeriveKek("bob", "pw", salt, new KdfSpec(KdfSpec.Argon2id, 1000, 1024, 1));
        Assert.NotEqual(alice, bob);
    }

    [Fact]
    public void DeriveKek_Pbkdf2_MatchesLegacyPbkdf2()
    {
        // レガシー経路: 旧 VolumeHeader.DeriveKek と同一（PBKDF2-SHA256, SHA256(username)||salt, 32B）
        byte[] salt = Enumerable.Repeat((byte)0x23, 16).ToArray();
        byte[] combined = KeyDerivation.CombineUserSalt("alice", salt);
        byte[] expected = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(
            "pw", combined, 100_000, System.Security.Cryptography.HashAlgorithmName.SHA256, 32);
        byte[] actual = KeyDerivation.DeriveKek("alice", "pw", salt, KdfSpec.LegacyPbkdf2(100_000));
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void KdfSpec_DefaultArgon2idRaw_IsValid()
    {
        Assert.True(KdfSpec.DefaultArgon2idRaw.IsArgon2idRaw);
        Assert.True(KdfSpec.DefaultArgon2idRaw.IsArgon2Family);
        Assert.True(KdfSpec.DefaultArgon2idRaw.IsValidArgon2Family());
        Assert.False(KdfSpec.DefaultArgon2idRaw.IsArgon2id);
        Assert.False(KdfSpec.DefaultArgon2idRaw.IsPbkdf2);
        Assert.Equal(0, KdfSpec.DefaultArgon2idRaw.Iterations);
    }

    [Fact]
    public void DeriveKek_Argon2idRaw_MatchesDirectArgon2id()
    {
        // 単独 KDF: KEK = Argon2id(pw, combinedSalt, t, m, p)（後段変換なし）
        byte[] salt = Enumerable.Repeat((byte)0x24, 16).ToArray();
        byte[] combined = KeyDerivation.CombineUserSalt("alice", salt);
        byte[] expected = Argon2idKdf.Derive("pw", combined, timeCost: 1, memoryKiB: 1024, parallelism: 1, length: 32);
        byte[] actual = KeyDerivation.DeriveKek("alice", "pw", salt, new KdfSpec(KdfSpec.Argon2idRaw, 0, 1024, 1, 1));
        Assert.Equal(expected, actual);

        // 出力長の伝播: 64 バイト出力でも直接 Argon2id と一致する
        byte[] expected64 = Argon2idKdf.Derive("pw", combined, 1, 1024, 1, 64);
        byte[] actual64 = KeyDerivation.DeriveKek("alice", "pw", salt, new KdfSpec(KdfSpec.Argon2idRaw, 0, 1024, 1, 1), outputLength: 64);
        Assert.Equal(expected64, actual64);
    }

    [Fact]
    public void DeriveKek_Argon2idRaw_DiffersFromComposite()
    {
        // 同一 t/m/p でも合成（PBKDF2 後段あり）とは別の鍵になること
        byte[] salt = Enumerable.Repeat((byte)0x25, 16).ToArray();
        byte[] raw = KeyDerivation.DeriveKek("alice", "pw", salt, new KdfSpec(KdfSpec.Argon2idRaw, 0, 1024, 1, 1));
        byte[] composite = KeyDerivation.DeriveKek("alice", "pw", salt, new KdfSpec(KdfSpec.Argon2id, 10, 1024, 1, 1));
        Assert.NotEqual(raw, composite);
    }

    [Fact]
    public void DeriveKek_Argon2idRaw_DifferentUser_ProducesDifferentKek()
    {
        byte[] salt = Enumerable.Repeat((byte)0x26, 16).ToArray();
        byte[] alice = KeyDerivation.DeriveKek("alice", "pw", salt, new KdfSpec(KdfSpec.Argon2idRaw, 0, 1024, 1, 1));
        byte[] bob = KeyDerivation.DeriveKek("bob", "pw", salt, new KdfSpec(KdfSpec.Argon2idRaw, 0, 1024, 1, 1));
        Assert.NotEqual(alice, bob);
    }

    [Fact]
    public void DeriveKek_Argon2idRaw_InvalidParams_Throws()
    {
        // t=0 は ValidateParams で拒否される
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            KeyDerivation.DeriveKek("alice", "pw", Enumerable.Repeat((byte)0x27, 16).ToArray(),
                new KdfSpec(KdfSpec.Argon2idRaw, 0, 1024, 1, timeCost: 0)));
    }
}
