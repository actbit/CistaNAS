using System.Text.Json;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public sealed class EncryptionSettingsReliabilityTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "cista-settings-reliable-" + Guid.NewGuid().ToString("N"));

    private EncryptionSettingsService CreateService(CistaNasOptions options)
    {
        options.DataRoot = _root;
        return new EncryptionSettingsService(Options.Create(options), NullLogger<EncryptionSettingsService>.Instance);
    }

    [Fact]
    public void EncryptionUpdate_PreservesFileSizeLimit_InMemoryAndAfterRestart()
    {
        var options = new CistaNasOptions { Volume = new VolumeOptions { MaxFileSizeBytes = 123_456 } };
        var service = CreateService(options);
        service.UpdateVolumeOptions(new UpdateEncryptionSettingsRequest(DefaultEncryptionMode: "e2ee"));
        Assert.Equal(123_456, options.Volume.MaxFileSizeBytes);

        var restored = new CistaNasOptions();
        CreateService(restored).LoadFromDiskIfExists();
        Assert.Equal(123_456, restored.Volume.MaxFileSizeBytes);
    }

    [Fact]
    public void SavedVolumeOptions_RestoreFileSizeLimit_AfterOtherSettingsSave()
    {
        var service = CreateService(new CistaNasOptions());
        service.SaveVolumeOptions(new VolumeOptions { MaxFileSizeBytes = 456_789 });
        service.SaveSharingOptions(false);
        var restored = new CistaNasOptions();
        CreateService(restored).LoadFromDiskIfExists();
        Assert.Equal(456_789, restored.Volume.MaxFileSizeBytes);
        Assert.False(restored.Sharing.Enabled);
    }

    [Fact]
    public void OlderSettingsWithoutFileSizeLimit_PreserveConfiguredLimit()
    {
        Directory.CreateDirectory(_root);
        File.WriteAllText(Path.Combine(_root, "cista-settings.json"), JsonSerializer.Serialize(new
        {
            Volume = new { SectorSize = 512, KdfIterations = 600_000, KdfMemoryKiB = 8192,
                KdfTimeCost = 1, KdfParallelism = 1, E2eeChunkSize = 1_048_576, ServerChunkSize = 4_194_304 }
        }));
        var options = new CistaNasOptions { Volume = new VolumeOptions { MaxFileSizeBytes = 234_567 } };
        CreateService(options).LoadFromDiskIfExists();
        Assert.Equal(234_567, options.Volume.MaxFileSizeBytes);
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    [InlineData(long.MaxValue)]
    public void InvalidPersistedLimit_DoesNotRelaxConfiguredLimit(long limit)
    {
        Directory.CreateDirectory(_root);
        File.WriteAllText(Path.Combine(_root, "cista-settings.json"), JsonSerializer.Serialize(new
        {
            Volume = new { MaxFileSizeBytes = limit, SectorSize = 512 }
        }));
        var options = new CistaNasOptions { Volume = new VolumeOptions { MaxFileSizeBytes = 123_456 } };
        CreateService(options).LoadFromDiskIfExists();
        Assert.Equal(123_456, options.Volume.MaxFileSizeBytes);
        Assert.Equal(4096, options.Volume.SectorSize);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
