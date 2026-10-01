using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Storage;

namespace CistaNAS.Tests;

public sealed class StorageRecoveryIdentityTests
{
    [Fact]
    public void AzureCredentialRotation_ReusesRecoveryDatabaseWithoutPersistingCredentials()
    {
        using var fixture = new Fixture();
        using var first = fixture.Create("https://account.blob.core.windows.net/db?sv=1&sig=old-secret", "tenant");
        CloudSqliteRecoveryTests.WriteValue(first.LocalDbPath, "not-yet-synced");
        using var rotated = fixture.Create("https://account.blob.core.windows.net/db?sv=2&sig=new-secret", "tenant/");
        Assert.Equal(first.LocalDbPath, rotated.LocalDbPath);
        using var db = CloudSqliteRecoveryTests.Open(rotated.LocalDbPath);
        Assert.Equal("not-yet-synced", CloudSqliteRecoveryTests.ReadValue(db));
        Assert.DoesNotContain("secret", first.LocalDbPath);
    }

    [Theory]
    [InlineData("https://other.blob.core.windows.net/db", "tenant")]
    [InlineData("https://account.blob.core.windows.net/other-db", "tenant")]
    [InlineData("https://account.blob.core.windows.net/db", "other-tenant")]
    public void DifferentAzureDestination_UsesDifferentRecoveryDatabase(string uri, string prefix)
    {
        using var fixture = new Fixture();
        using var first = fixture.Create("https://account.blob.core.windows.net/db", "tenant");
        using var second = fixture.Create(uri, prefix);
        Assert.NotEqual(first.LocalDbPath, second.LocalDbPath);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), $"cista-identity-{Guid.NewGuid():N}");
        public CloudSqliteSync Create(string uri, string prefix) => new(
            new AzureBlobStorageProvider(new PassiveContainer(new Uri(uri)), prefix),
            new StorageOptions { VolumeDataPath = _root }, new DatabaseOptions());
        public void Dispose() => Directory.Delete(_root, true);
    }

    // Models only the endpoint and the existing eager initialization, without cloud I/O.
    private sealed class PassiveContainer(Uri endpoint) : BlobContainerClient
    {
        public override Uri Uri => endpoint;
        public override Task<Response<BlobContainerInfo>> CreateIfNotExistsAsync(PublicAccessType publicAccessType = PublicAccessType.None,
            IDictionary<string, string>? metadata = null, BlobContainerEncryptionScopeOptions? encryptionScopeOptions = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult<Response<BlobContainerInfo>>(null!);
    }
}
