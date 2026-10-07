using System.Text;
using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Journal;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;

namespace CistaNAS.Tests;

public sealed class JournalCorruptionRegressionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "cista-journal-corrupt-" + Guid.NewGuid().ToString("N"));

    public static IEnumerable<object[]> CorruptJournals()
    {
        foreach (string json in new[] { "null", "{}", "{\"Pending\":null}", "{\"Pending\":[null]}", "{\"Pending\":[{\"Operation\":999}]}" })
        foreach (string operation in new[] { "recover", "has-pending", "record", "commit", "commit-all" })
            yield return [json, operation];
    }

    [Theory]
    [MemberData(nameof(CorruptJournals))]
    public async Task InvalidJournal_BlocksOperationsWithoutOverwritingRecoveryEvidence(string json, string operation)
    {
        var storage = new LocalStorageProvider(_root);
        var service = new JournalService(storage);
        byte[] original = Encoding.UTF8.GetBytes(json);
        await storage.WriteAtomicAsync("vol/volume.journal", new MemoryStream(original));
        Func<Task> run = operation switch
        {
            "recover" => () => service.RecoverAsync("vol"),
            "has-pending" => () => service.HasPendingAsync("vol"),
            "record" => () => service.RecordAsync("vol", new JournalEntry { Operation = JournalOp.WriteFile, Path = "new" }),
            "commit" => () => service.CommitAsync("vol", "operation"),
            _ => () => service.CommitAllAsync("vol"),
        };
        await Assert.ThrowsAsync<InvalidDataException>(run);
        Assert.Equal(original, await storage.ReadAsync("vol/volume.journal"));
    }

    [Theory]
    [InlineData("null", "append")]
    [InlineData("null", "drain")]
    [InlineData("null", "read")]
    [InlineData("{}", "append")]
    [InlineData("{}", "drain")]
    [InlineData("{}", "read")]
    public void LegacyFileHelpers_PreserveInvalidJournals(string json, string operation)
    {
        Directory.CreateDirectory(_root);
        string path = Path.Combine(_root, "volume.journal");
        File.WriteAllText(path, json);
        Assert.Throws<InvalidDataException>(() =>
        {
            if (operation == "append") JournalFile.Append(path, new JournalEntry { Path = "new" });
            else if (operation == "drain") JournalFile.Drain(path);
            else JournalFile.Read(path);
        });
        Assert.Equal(json, File.ReadAllText(path));
    }

    [Fact]
    public async Task ValidLegacyEntriesWithoutOperationIds_CanStillBeRecoveredAndCommitted()
    {
        var storage = new LocalStorageProvider(_root);
        var service = new JournalService(storage);
        await storage.WriteAtomicAsync("vol/volume.journal", new MemoryStream(
            "{\"Pending\":[{\"Operation\":1,\"Path\":\"old.txt\"}]}"u8.ToArray()));
        Assert.True(await service.HasPendingAsync("vol"));
        var entry = Assert.Single(await service.RecoverAsync("vol"));
        Assert.Equal(JournalOp.DeleteFile, entry.Operation);
        Assert.Null(entry.OperationId);
        await service.CommitAllAsync("vol");
        Assert.Empty(await service.RecoverAsync("vol"));
    }

    [Theory]
    [InlineData("plain")]
    [InlineData("server")]
    [InlineData("e2ee")]
    public async Task InvalidJournal_AbortsMountAndReleasesResourcesForRetry(string mode)
    {
        var (provider, dataRoot) = TestHelper.BuildTestServices();
        try
        {
            await using var services = (ServiceProvider)provider;
            var volumes = services.GetRequiredService<VolumeService>();
            var storage = services.GetRequiredService<IStorageProvider>();
            await using var scope = services.CreateAsyncScope();
            var files = scope.ServiceProvider.GetRequiredService<FileService>();
            string name = "journal-" + Guid.NewGuid().ToString("N");
            byte[] content = "committed data must survive a rejected mount"u8.ToArray();
            if (mode == "e2ee")
            {
                byte[] masterKey = E2eeCrypto.GenerateMasterKey();
                byte[] kek = RandomNumberGenerator.GetBytes(32);
                var (nonce, ciphertext, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
                CryptographicOperations.ZeroMemory(masterKey);
                CryptographicOperations.ZeroMemory(kek);
                await volumes.CreateE2eeAsync(name, "owner", new VolumeHeader.UserWrappedKey
                {
                    WrappedMasterKey = new() { Nonce = nonce, Ciphertext = ciphertext, Tag = tag },
                });
            }
            else
            {
                await volumes.CreateAsync(name, "owner", "password", encrypted: mode == "server");
                await files.UploadAsync(name, "keep.txt", new MemoryStream(content), content.Length);
            }
            await volumes.LockAsync(name, "owner");
            byte[] invalid = "{}"u8.ToArray();
            await storage.WriteAtomicAsync(name + "/volume.journal", new MemoryStream(invalid));
            Func<Task> mount = mode == "e2ee"
                ? () => volumes.MountE2eeAsync(name, "owner")
                : () => volumes.MountAsync(name, "owner", "password");

            await Assert.ThrowsAsync<VolumeException>(mount);
            Assert.False(volumes.IsMounted(name));
            Assert.Equal(invalid, await storage.ReadAsync(name + "/volume.journal"));
            // Failed recovery must release any exclusive server-side stream.
            // Authenticated server encryption now uses chunk storage, so there may be no volume.dat.
            string volumePath = Path.Combine(dataRoot, name, "volume.dat");
            if (File.Exists(volumePath))
                using (File.Open(volumePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }

            await storage.WriteAtomicAsync(name + "/volume.journal", new MemoryStream("{\"Pending\":[]}"u8.ToArray()));
            await mount();
            Assert.True(volumes.IsMounted(name));
            if (mode != "e2ee")
            {
                var download = await files.DownloadAsync(name, "keep.txt");
                await using var stream = download.Stream;
                byte[] actual = new byte[content.Length];
                await stream.ReadExactlyAsync(actual);
                Assert.Equal(content, actual);
            }
        }
        finally
        {
            if (Directory.Exists(dataRoot)) Directory.Delete(dataRoot, recursive: true);
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
