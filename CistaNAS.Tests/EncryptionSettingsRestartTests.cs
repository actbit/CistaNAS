using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

/// <summary>
/// 暗号化・共有設定 (cista-settings.json) の永続化を「サーバー再起動シミュレーション」で検証する。
/// 保存後に新しい CistaNasOptions / EncryptionSettingsService インスタンス（= 再起動後のプロセス相当）
/// で LoadFromDiskIfExists() を呼び、設定が復元されることを直接確認する。
/// </summary>
public class EncryptionSettingsRestartTests
{
    /// <summary>再起動前のプロセス相当（オプション + サービス）を構築する。</summary>
    private static (CistaNasOptions Options, EncryptionSettingsService Service) BuildProcess(string dataRoot)
    {
        var options = new CistaNasOptions
        {
            DataRoot = dataRoot,
            Volume = new VolumeOptions
            {
                SectorSize = 512,
                KdfAlgorithm = KdfSpec.Argon2id,
                KdfIterations = 600_000,
                KdfMemoryKiB = 8192,
                KdfTimeCost = 1,
                KdfParallelism = 1,
            },
            Auth = new AuthOptions { Pbkdf2Iterations = 10_000 },
        };
        var service = new EncryptionSettingsService(
            Options.Create(options), NullLogger<EncryptionSettingsService>.Instance);
        return (options, service);
    }

    // ---- 項目 4: Global SharingEnabled の再起動後永続化 ----

    [Fact]
    public void GlobalSharingDisabled_SurvivesRestart()
    {
        string dataRoot = Path.Combine(Path.GetTempPath(), "cista-settings-" + Guid.NewGuid().ToString("N"));
        try
        {
            // 1 つ目の「プロセス」で共有を無効化して保存
            var (options1, service1) = BuildProcess(dataRoot);
            Assert.True(options1.Sharing.Enabled); // 既定は有効
            service1.SaveSharingOptions(enabled: false);
            Assert.False(options1.Sharing.Enabled);

            // cista-settings.json が DataRoot 配下に作られていること
            Assert.True(File.Exists(Path.Combine(dataRoot, "cista-settings.json")));

            // 2 つ目の「プロセス」（新しいオプション + サービス）で起動時ロード
            var (options2, service2) = BuildProcess(dataRoot);
            Assert.True(options2.Sharing.Enabled); // デフォルト値から出発
            service2.LoadFromDiskIfExists();

            Assert.False(options2.Sharing.Enabled, "再起動後に Global SharingEnabled=false が復元されませんでした");
            Assert.False(service2.CurrentSharingOptions().Enabled);
        }
        finally
        {
            if (Directory.Exists(dataRoot)) Directory.Delete(dataRoot, recursive: true);
        }
    }

    [Fact]
    public void GlobalSharingToggle_SurvivesRestart()
    {
        string dataRoot = Path.Combine(Path.GetTempPath(), "cista-settings-" + Guid.NewGuid().ToString("N"));
        try
        {
            var (_, service1) = BuildProcess(dataRoot);
            service1.SaveSharingOptions(enabled: false);
            service1.SaveSharingOptions(enabled: true); // 無効化 → 再有効化の往復

            var (_, service2) = BuildProcess(dataRoot);
            service2.LoadFromDiskIfExists();
            Assert.True(service2.CurrentSharingOptions().Enabled);

            service1.SaveSharingOptions(enabled: false);
            var (_, service3) = BuildProcess(dataRoot);
            service3.LoadFromDiskIfExists();
            Assert.False(service3.CurrentSharingOptions().Enabled);
        }
        finally
        {
            if (Directory.Exists(dataRoot)) Directory.Delete(dataRoot, recursive: true);
        }
    }

    // ---- ボリューム設定も同じファイルで永続化される（共有設定保存で消えないこと） ----

    [Fact]
    public void VolumeOptions_SurviveRestart_AndSharingSaveKeepsThem()
    {
        string dataRoot = Path.Combine(Path.GetTempPath(), "cista-settings-" + Guid.NewGuid().ToString("N"));
        try
        {
            var (options1, service1) = BuildProcess(dataRoot);
            var vol = new VolumeOptions
            {
                SectorSize = 4096,
                KdfAlgorithm = KdfSpec.Argon2idRaw,
                KdfIterations = 0, // argon2id-raw では不使用
                KdfMemoryKiB = 65536,
                KdfTimeCost = 4,
                KdfParallelism = 2,
                DefaultEncryptionMode = "e2ee",
                E2eeChunkSize = 4_194_304,
            };
            service1.SaveVolumeOptions(vol);
            service1.SaveSharingOptions(enabled: false); // 後から共有設定だけ保存

            var (options2, service2) = BuildProcess(dataRoot);
            service2.LoadFromDiskIfExists();

            // 共有設定
            Assert.False(options2.Sharing.Enabled);
            // 先に保存したボリューム設定が共有設定の保存で消えずに復元されること
            Assert.Equal(vol.SectorSize, options2.Volume.SectorSize);
            Assert.Equal(vol.KdfAlgorithm, options2.Volume.KdfAlgorithm);
            Assert.Equal(vol.KdfIterations, options2.Volume.KdfIterations);
            Assert.Equal(vol.KdfMemoryKiB, options2.Volume.KdfMemoryKiB);
            Assert.Equal(vol.KdfTimeCost, options2.Volume.KdfTimeCost);
            Assert.Equal(vol.KdfParallelism, options2.Volume.KdfParallelism);
            Assert.Equal(vol.DefaultEncryptionMode, options2.Volume.DefaultEncryptionMode);
            Assert.Equal(vol.E2eeChunkSize, options2.Volume.E2eeChunkSize);
        }
        finally
        {
            if (Directory.Exists(dataRoot)) Directory.Delete(dataRoot, recursive: true);
        }
    }

    // ---- 破損ファイル・欠損ファイルへの耐性（fail closed / fail safe） ----

    [Fact]
    public void CorruptSettingsFile_DoesNotThrow_AndIsBackedUp()
    {
        string dataRoot = Path.Combine(Path.GetTempPath(), "cista-settings-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataRoot);
        try
        {
            // 中途切れの破損 JSON（原子書込みがない実装でクラッシュ時に発生しうる形）
            File.WriteAllText(Path.Combine(dataRoot, "cista-settings.json"), "{\"Volume\": {\"Sector");

            var (options, service) = BuildProcess(dataRoot);
            // 例外を投げずに既定値で起動できること（起動不能 = サービス全体のデータ欠損）
            service.LoadFromDiskIfExists();

            Assert.True(options.Sharing.Enabled);   // 既定値のまま
            Assert.Equal(512, options.Volume.SectorSize);

            // 破損ファイルは次回保存時にバックアップされる（サイレント上書き消去でないこと）
            service.SaveSharingOptions(enabled: true);
            Assert.True(File.Exists(Path.Combine(dataRoot, "cista-settings.json.bak")));
        }
        finally
        {
            if (Directory.Exists(dataRoot)) Directory.Delete(dataRoot, recursive: true);
        }
    }

    [Fact]
    public void MissingSettingsFile_LoadIsNoOp()
    {
        string dataRoot = Path.Combine(Path.GetTempPath(), "cista-settings-" + Guid.NewGuid().ToString("N"));
        try
        {
            var (options, service) = BuildProcess(dataRoot);
            service.LoadFromDiskIfExists(); // ファイル無し → 何もしない
            Assert.True(options.Sharing.Enabled);
            Assert.Equal(512, options.Volume.SectorSize);
        }
        finally
        {
            if (Directory.Exists(dataRoot)) Directory.Delete(dataRoot, recursive: true);
        }
    }
}
