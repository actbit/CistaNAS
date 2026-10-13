using Amazon.S3;
using Amazon.S3.Model;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Storage;

namespace CistaNAS.Tests;

public sealed class S3ConditionalRequestTests
{
    [Theory]
    [InlineData(true, true, true)]
    [InlineData(false, true, true)]
    [InlineData(true, false, true)]
    [InlineData(true, true, false)]
    [InlineData(false, false, false)]
    public async Task LockRequests_RespectEachConditionalRequestFlag(
        bool putIfNoneMatch, bool putIfMatch, bool deleteIfMatch)
    {
        using var client = new RecordingS3Client();
        await using var storage = new S3StorageProvider(
            "bucket", "us-east-1", null, null, client,
            new S3ConditionalRequestOptions
            {
                PutIfNoneMatch = putIfNoneMatch,
                PutIfMatch = putIfMatch,
                DeleteIfMatch = deleteIfMatch,
            });

        using (var lockHandle = await storage.AcquireLockAsync("test-lock"))
        {
            var releaser = Assert.IsType<S3StorageProvider.S3LockReleaser>(lockHandle);
            await releaser.RenewAsync();
        }

        Assert.Equal(2, client.PutRequests.Count);
        Assert.Equal(putIfNoneMatch ? "*" : null, client.PutRequests[0].IfNoneMatch);
        Assert.Equal(putIfMatch ? "\"lock-etag\"" : null, client.PutRequests[1].IfMatch);

        Assert.Single(client.DeleteRequests);
        Assert.Equal(deleteIfMatch ? "\"lock-etag\"" : null, client.DeleteRequests[0].IfMatch);
    }

    [Fact]
    public void Defaults_EnableAllConditionalRequests()
    {
        var options = new S3ConditionalRequestOptions();

        Assert.True(options.PutIfNoneMatch);
        Assert.True(options.PutIfMatch);
        Assert.True(options.DeleteIfMatch);
    }

    private sealed class RecordingS3Client : AmazonS3Client
    {
        public List<PutObjectRequest> PutRequests { get; } = [];
        public List<DeleteObjectRequest> DeleteRequests { get; } = [];

        public RecordingS3Client()
            : base(new AmazonS3Config { RegionEndpoint = Amazon.RegionEndpoint.USEast1 }) { }

        public override Task<PutObjectResponse> PutObjectAsync(
            PutObjectRequest request, CancellationToken cancellationToken = default)
        {
            PutRequests.Add(request);
            return Task.FromResult(new PutObjectResponse { ETag = "\"lock-etag\"" });
        }

        public override Task<DeleteObjectResponse> DeleteObjectAsync(
            DeleteObjectRequest request, CancellationToken cancellationToken = default)
        {
            DeleteRequests.Add(request);
            return Task.FromResult(new DeleteObjectResponse());
        }
    }
}
