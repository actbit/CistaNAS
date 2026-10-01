using CistaNAS.Web.Configuration;
using CistaNAS.Web.Storage;

namespace CistaNAS.Tests;

public sealed class CloudSqliteIsolationTests
{
    [Fact]
    public void LegacyDatabaseAtFilesystemRoot_IsRecognizedForMigration()
    {
        string root = Path.GetPathRoot(Path.GetTempPath())!;
        Assert.Equal(Path.Combine(root, "cista.db"), CloudSqliteSync.GetLegacyPath(root, "cista.db"));
    }

    [Fact]
    public void LegacyDatabaseOutsideConfiguredRoot_IsPreservedInsteadOfIgnored()
    {
        using var fixture = new Fixture(false);
        var storage = new LocalStorageProvider(Path.Combine(fixture.Root, "cloud"));
        var options = new StorageOptions { VolumeDataPath = fixture.Local };
        var database = new DatabaseOptions { BlobKey = "../legacy.db" };
        using var probe = new CloudSqliteSync(storage, options, database);
        string legacy = Path.Combine(fixture.Root, "legacy.db");
        File.WriteAllText(legacy, "unsynced-legacy-data");
        var error = Assert.Throws<InvalidOperationException>(() => new CloudSqliteSync(storage, options, database));
        Assert.Contains(legacy, error.Message);
        Assert.Equal("unsynced-legacy-data", File.ReadAllText(legacy));
        Assert.False(File.Exists(probe.LocalDbPath));
    }

    [Theory]
    [InlineData("../metadata.db")]
    [InlineData("nested/metadata.db")]
    public void CloudObjectName_DoesNotChooseLocalRecoveryPath(string key)
    {
        using var fixture = new Fixture(false);
        var storage = new LocalStorageProvider(Path.Combine(fixture.Root, "cloud"));
        using var sync = new CloudSqliteSync(storage, new StorageOptions { VolumeDataPath = fixture.Local },
            new DatabaseOptions { BlobKey = key });
        Assert.StartsWith(fixture.Local + Path.DirectorySeparatorChar, sync.LocalDbPath);
        Assert.Equal("database.sqlite", Path.GetFileName(sync.LocalDbPath));
        CloudSqliteRecoveryTests.WriteValue(sync.LocalDbPath, "private");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DifferentDestinations_DoNotUploadAnotherDatabasesPrivateData(bool temporary)
    {
        using var fixture = new Fixture(temporary);
        var firstStorage = new LocalStorageProvider(Path.Combine(fixture.Root, "first-cloud"));
        var secondStorage = new LocalStorageProvider(Path.Combine(fixture.Root, "second-cloud"));
        string seed = Path.Combine(fixture.Root, "seed.sqlite");
        CloudSqliteRecoveryTests.WriteValue(seed, "second-private");
        await using (var input = File.OpenRead(seed))
            await secondStorage.WriteAtomicAsync(fixture.Key, input);
        using var first = fixture.Create(firstStorage);
        fixture.Track(first);
        CloudSqliteRecoveryTests.WriteValue(first.LocalDbPath, "first-private");
        first.MarkDirty();
        await first.UploadIfDirtyAsync();
        using var second = fixture.Create(secondStorage);
        fixture.Track(second);
        await second.DownloadAsync();
        await second.UploadIfDirtyAsync();
        string received = Path.Combine(fixture.Root, "received.sqlite");
        await File.WriteAllBytesAsync(received, (await secondStorage.ReadAsync(fixture.Key))!);
        using var db = CloudSqliteRecoveryTests.Open(received);
        Assert.Equal("second-private", CloudSqliteRecoveryTests.ReadValue(db));
        Assert.NotEqual(first.LocalDbPath, second.LocalDbPath);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SameDestination_RestartPreservesUnsyncedLocalChanges(bool temporary)
    {
        using var fixture = new Fixture(temporary);
        string cloud = Path.Combine(fixture.Root, "cloud");
        using var first = fixture.Create(new LocalStorageProvider(cloud));
        fixture.Track(first);
        CloudSqliteRecoveryTests.WriteValue(first.LocalDbPath, "pending-local");
        using var second = fixture.Create(new LocalStorageProvider(cloud));
        fixture.Track(second);
        await second.DownloadAsync();
        Assert.Equal(first.LocalDbPath, second.LocalDbPath);
        using var db = CloudSqliteRecoveryTests.Open(second.LocalDbPath);
        Assert.Equal("pending-local", CloudSqliteRecoveryTests.ReadValue(db));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnboundLegacyDatabase_StopsStartupAndPreservesOriginal(bool temporary)
    {
        using var fixture = new Fixture(temporary);
        var storage = new LocalStorageProvider(Path.Combine(fixture.Root, "cloud"));
        using var probe = fixture.Create(storage);
        fixture.Track(probe);
        string legacy = Path.Combine(temporary ? Path.GetTempPath() : fixture.Local, fixture.Key);
        File.WriteAllText(legacy, "legacy-unsynced-data");
        fixture.Legacy = legacy;
        var error = Assert.Throws<InvalidOperationException>(() => fixture.Create(storage));
        Assert.Contains(legacy, error.Message);
        Assert.Contains(probe.LocalDbPath, error.Message);
        Assert.Equal("legacy-unsynced-data", File.ReadAllText(legacy));
        Assert.False(File.Exists(probe.LocalDbPath));
    }

    private sealed class Fixture(bool temporary) : IDisposable
    {
        private readonly HashSet<string> _paths = [];
        public string Root { get; } = Path.Combine(Path.GetTempPath(), $"cista-isolation-{Guid.NewGuid():N}");
        public string Key { get; } = $"recovery-{Guid.NewGuid():N}.db";
        public string Local => Path.Combine(Root, "local");
        public string? Legacy { get; set; }
        public CloudSqliteSync Create(IStorageProvider storage)
        {
            Directory.CreateDirectory(Local);
            return new(storage, new StorageOptions { VolumeDataPath = temporary ? null : Local },
                new DatabaseOptions { BlobKey = Key });
        }
        public void Track(CloudSqliteSync sync) => _paths.Add(sync.LocalDbPath);
        public void Dispose()
        {
            foreach (string path in _paths)
            {
                File.Delete(path);
                File.Delete(path + "-wal");
                File.Delete(path + "-shm");
                if (temporary && Path.GetDirectoryName(path) != Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar))
                    Directory.Delete(Path.GetDirectoryName(path)!);
            }
            if (Legacy is not null) File.Delete(Legacy);
            Directory.Delete(Root, true);
        }
    }
}
