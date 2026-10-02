using CistaNAS.Web.Configuration;
using CistaNAS.Web.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public sealed class EncryptionSettingsConcurrencyTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "cista-settings-concurrent-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task ConcurrentSectionUpdates_PreserveEverySuccessfulSave_AfterRestart()
    {
        var options = new CistaNasOptions { DataRoot = _root };
        var service = new EncryptionSettingsService(Options.Create(options), NullLogger<EncryptionSettingsService>.Instance);

        for (int round = 0; round < 24; round++)
        {
            service.SaveVolumeOptions(new VolumeOptions());
            service.SaveAuthOptions(new AuthOptions());
            service.SaveSharingOptions(true);
            using var start = new Barrier(3);
            Task Run(Action save) => Task.Factory.StartNew(() =>
            {
                Assert.True(start.SignalAndWait(TimeSpan.FromSeconds(10)));
                save();
            }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

            await Task.WhenAll(
                Run(() => service.SaveVolumeOptions(new VolumeOptions { E2eeChunkSize = 4_194_304, MaxFileSizeBytes = 123_456 })),
                Run(() => service.SaveAuthOptions(new AuthOptions { DefaultAdminUser = "updated-owner" })),
                Run(() => service.SaveSharingOptions(false)));

            var restored = new CistaNasOptions { DataRoot = _root };
            new EncryptionSettingsService(Options.Create(restored), NullLogger<EncryptionSettingsService>.Instance).LoadFromDiskIfExists();
            Assert.Equal(4_194_304, restored.Volume.E2eeChunkSize);
            Assert.Equal(123_456, restored.Volume.MaxFileSizeBytes);
            Assert.Equal("updated-owner", restored.Auth.DefaultAdminUser);
            Assert.False(restored.Sharing.Enabled);
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
