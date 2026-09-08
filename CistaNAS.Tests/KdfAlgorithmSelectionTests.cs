using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Volume;
using Xunit;

namespace CistaNAS.Tests;

/// <summary>
/// KDF 種別選択（argon2id = Argon2id+PBKDF2 合成 / argon2id-raw = Argon2id 単独）の
/// ヘッダラウンドトリップとサーバー設定 dispatch の検証。
/// </summary>
public class KdfAlgorithmSelectionTests
{
    private static VolumeHeader NewE2eeHeaderWithWrap(string algorithm, int iterations, int memoryKiB, int parallelism, int timeCost)
    {
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        var header = new VolumeHeader
        {
            Name = $"vol-{algorithm}",
            Encrypted = true,
            EncryptionMode = "e2ee",
            StorageMode = "chunk",
            ChunkSize = 1048576,
            SectorSize = 0,
            OwnerUser = "alice",
        };
        var spec = new KdfSpec(algorithm, iterations, memoryKiB, parallelism, timeCost);
        header.AddUserWrap("alice", "correct-password", masterKey, spec);
        return header;
    }

    [Fact]
    public void VolumeHeader_Argon2idRaw_UnlockRoundtrip()
    {
        VolumeHeader header = NewE2eeHeaderWithWrap(KdfSpec.Argon2idRaw, iterations: 0, memoryKiB: 1024, parallelism: 1, timeCost: 1);

        // ヘッダに正しい KDF 種別が永続化され、正しいパスワードでアンラップできる
        Assert.Equal(KdfSpec.Argon2idRaw, header.UserKeys["alice"].Kdf.Algorithm);
        Assert.Equal(0, header.UserKeys["alice"].Kdf.Iterations);
        byte[] masterKey = header.UnwrapMasterKey("alice", "correct-password")!;
        Assert.Equal(32, masterKey.Length);
        CryptographicOperations.ZeroMemory(masterKey);

        Assert.Null(header.UnwrapMasterKey("alice", "wrong-password"));
    }

    [Fact]
    public void VolumeHeader_Argon2idRaw_OverVerifyLimit_ReturnsNull()
    {
        VolumeHeader header = NewE2eeHeaderWithWrap(KdfSpec.Argon2idRaw, iterations: 0, memoryKiB: 65536, parallelism: 4, timeCost: 4);

        // ヘッダ改ざん（TimeCost を検証上限超に書き換え）→ DoS 対策でアンラップを拒否
        header.UserKeys["alice"].Kdf.TimeCost = Argon2idKdf.MaxVerifyTimeCost + 1;
        Assert.Null(header.UnwrapMasterKey("alice", "correct-password"));
    }

    [Fact]
    public void VolumeHeader_CompositeAndLegacy_StillUnlockAfterRawIntroduced()
    {
        // argon2id-raw 追加後も既存 2 種別（合成・レガシー PBKDF2）が変わらずアンラップできること
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();

        var compositeHeader = new VolumeHeader
        {
            Name = "vol-composite", Encrypted = true, EncryptionMode = "e2ee",
            StorageMode = "chunk", ChunkSize = 1048576, SectorSize = 0, OwnerUser = "alice",
        };
        compositeHeader.AddUserWrap("alice", "pw", masterKey, new KdfSpec(KdfSpec.Argon2id, 10, 1024, 1, 1));
        Assert.Equal(masterKey, compositeHeader.UnwrapMasterKey("alice", "pw"));

        var legacyHeader = new VolumeHeader
        {
            Name = "vol-legacy", Encrypted = true, EncryptionMode = "e2ee",
            StorageMode = "chunk", ChunkSize = 1048576, SectorSize = 0, OwnerUser = "alice",
        };
        legacyHeader.AddUserWrap("alice", "pw", masterKey, KdfSpec.LegacyPbkdf2(100_000));
        Assert.Equal(masterKey, legacyHeader.UnwrapMasterKey("alice", "pw"));
    }

    [Fact]
    public void VolumeOptions_ToKdfSpec_DispatchesByAlgorithm()
    {
        // 既定: Argon2id+PBKDF2 合成
        var composite = new VolumeOptions();
        Assert.Equal(KdfSpec.DefaultArgon2id, composite.ToKdfSpec());

        // argon2id-raw: Iterations は不使用（0 で永続化）
        var raw = new VolumeOptions
        {
            KdfAlgorithm = KdfSpec.Argon2idRaw,
            KdfIterations = 600_000,
            KdfMemoryKiB = 16384,
            KdfTimeCost = 1,
            KdfParallelism = 1,
        };
        KdfSpec rawSpec = raw.ToKdfSpec();
        Assert.Equal(KdfSpec.Argon2idRaw, rawSpec.Algorithm);
        Assert.Equal(0, rawSpec.Iterations);
        Assert.Equal(16384, rawSpec.MemoryKiB);
        Assert.Equal(1, rawSpec.TimeCost);
        Assert.Equal(1, rawSpec.Parallelism);

        // 未知の値は合成にフォールバック（設定改ざん時の安全側）
        var unknown = new VolumeOptions { KdfAlgorithm = "scrypt" };
        Assert.Equal(KdfSpec.Argon2id, unknown.ToKdfSpec().Algorithm);
    }
}
