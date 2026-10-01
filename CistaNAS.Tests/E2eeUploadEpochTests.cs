using System.Reflection;
using System.Net.Http.Json;
using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Api;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public partial class E2eeFileTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DokanV2Save_DuringRewrap_RemainsDecryptable(bool chunkMode)
    {
        _sp.GetRequiredService<IOptions<CistaNasOptions>>().Value.Storage.Provider = chunkMode ? "s3" : "local";
        string volume = await MountE2eeAsync("dokan-epoch");
        var service = GetE2eeFileService();
        var (header, _) = _volumeService.GetMountedKeys(volume);
        string volumeId = header.EnsureVolumeId();
        header.AddGroupEpoch(1, []);
        byte[] fileKey = E2eeV2.GenerateFileKey(), group1 = E2eeV2.GenerateGroupKey(), group2 = E2eeV2.GenerateGroupKey();
        byte[] salt = E2eeV2.GenerateFileSalt();
        string fileId = Guid.NewGuid().ToString("N");
        var entry = await service.CreateFileAsync(volume,
            new E2eeCreateFileRequest(E2eeCrypto.EncryptFilename("file.txt", group1), 35, 1, 1,
                WrapForEpoch(fileKey, group1, volumeId, fileId, 1)), "testuser", preallocatedFileId: fileId);
        byte[] initial = E2eeV2.EncryptChunk([1, 2, 3], fileKey,
            new E2eeChunkContext(volumeId, fileId, 0, 0, 1), true, salt);
        using (var source = new MemoryStream(initial))
            await service.UploadChunkAsync(volume, fileId, 0, source, initial.Length);
        await service.FinalizeFileAsync(volume, fileId, new E2eeFinalizeFileRequest(initial.Length, 1));
        var leases = new E2eeWriteLeaseService(_sp.GetRequiredService<IStorageProvider>());
        bool rotateOnHash = false;
        using var handler = new EpochHttpHandler(async request =>
        {
            string path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/files")) return new(HttpStatusCode.OK) { Content = JsonContent.Create(await service.ListFilesAsync(volume)) };
            if (path.EndsWith("/write-lease"))
            {
                if (request.Method == HttpMethod.Post)
                    return new(HttpStatusCode.OK) { Content = JsonContent.Create(await leases.AcquireAsync(volume, fileId)) };
                await leases.ReleaseAsync(volume, fileId, request.Headers.GetValues(E2eeWriteLeaseService.HeaderName).Single());
                return new(HttpStatusCode.NoContent);
            }
            if (path.Contains("/download-chunk/"))
            {
                var (stream, length, revision, epoch) = await service.DownloadChunkAsync(volume, fileId, 0);
                using (stream)
                {
                    byte[] bytes = new byte[length];
                    await stream.ReadExactlyAsync(bytes);
                    var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) };
                    response.Headers.Add("X-Chunk-Revision", revision.ToString());
                    response.Headers.Add("X-Chunk-KeyEpoch", epoch.ToString());
                    return response;
                }
            }
            if (path.Contains("/chunk-hash/"))
            {
                var (hash, revision) = await service.GetChunkHashAsync(volume, fileId, 0);
                if (rotateOnHash)
                {
                    rotateOnHash = false;
                    header.AddGroupEpoch(2, []);
                    await service.RewrapFileKeysAsync(volume,
                        new E2eeRewrapFileKeysRequest([new(fileId, 2, WrapForEpoch(fileKey, group2, volumeId, fileId, 2))]), "testuser");
                }
                return new(HttpStatusCode.OK) { Content = JsonContent.Create(new { hash, revision }) };
            }
            if (path.Contains("/upload-chunk/"))
            {
                var ctx = new DefaultHttpContext();
                using var body = new MemoryStream(await request.Content!.ReadAsByteArrayAsync());
                ctx.Request.Body = body;
                ctx.Request.ContentLength = body.Length;
                foreach (var item in request.Headers) ctx.Request.Headers[item.Key] = item.Value.ToArray();
                var result = await InvokeEpochUploadEndpointAsync(service, volume, fileId, leases, ctx.Request);
                return new((HttpStatusCode)((IStatusCodeHttpResult)result).StatusCode!);
            }
            if (path.Contains("/finalize-file/"))
            {
                var finalize = await request.Content!.ReadFromJsonAsync<E2eeFinalizeFileRequest>();
                await service.FinalizeFileAsync(volume, fileId, finalize!);
                return new(HttpStatusCode.OK);
            }
            throw new InvalidOperationException(path);
        });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://test/") };
        await Task.Run(() =>
        {
            using var state = new CistaNAS.Client.Security.E2eeV2VolumeState(volumeId,
                new Dictionary<int, byte[]> { [1] = group1, [2] = group2 });
            using var fs = new CistaNAS.Client.CistaNasFileSystem(new CistaNAS.Client.Api.CistaNasApiClient(http),
                null, volume, 4096, state);
            var write = new CistaNAS.Client.CistaNasFileSystem.E2eeChunkWriteState(fs, "file.txt", fileId);
            try
            {
                write.Write([4, 5, 6], 0, 3, 0);
                rotateOnHash = true;
                fs.UploadWriteState(write);
            }
            finally { write.Dispose(); }
        });
        var (saved, savedLength, savedRevision, savedEpoch) = await service.DownloadChunkAsync(volume, fileId, 0);
        using (saved)
        {
            byte[] bytes = new byte[savedLength];
            await saved.ReadExactlyAsync(bytes);
            Assert.Equal(new byte[] { 4, 5, 6 }, E2eeV2.DecryptChunk(bytes, fileKey,
                new E2eeChunkContext(volumeId, fileId, 0, savedRevision, savedEpoch), salt));
        }
        Assert.Equal(1, savedEpoch);
        CryptographicOperations.ZeroMemory(fileKey);
    }

    private sealed class EpochHttpHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task NewSharedFile_CannotUseAnObsoleteKeyEpoch(int epoch)
    {
        string volume = await MountE2eeAsync("obsolete-epoch");
        var (header, _) = _volumeService.GetMountedKeys(volume);
        header.EnsureVolumeId();
        header.AddGroupEpoch(1, []);
        header.AddGroupEpoch(2, []);
        var service = GetE2eeFileService();
        await Assert.ThrowsAsync<FileServiceException>(() => service.CreateFileAsync(volume,
            new E2eeCreateFileRequest("enc", 35, 1, epoch, epoch == 0 ? null : ShapeOnlyWrappedKey()), "testuser"));
        Assert.Empty((await service.ListFilesAsync(volume)).Files);
    }

    [Fact]
    public async Task RewrappingLegacyFile_CannotSilentlyChangeItsCryptoFormat()
    {
        string volume = await MountE2eeAsync("legacy-rewrap");
        var service = GetE2eeFileService();
        byte[] salt = E2eeCrypto.GenerateFileSalt();
        byte[] key = E2eeCrypto.DeriveFileKey(_masterKey, salt);
        byte[] expected = [1, 2, 3];
        byte[] encrypted = E2eeCrypto.EncryptChunk(expected, key, 0, salt, true);
        var entry = await service.CreateFileAsync(volume, new E2eeCreateFileRequest("enc", encrypted.Length, 1), "testuser");
        using (var source = new MemoryStream(encrypted))
            await service.UploadChunkAsync(volume, entry.FileId, 0, source, encrypted.Length);
        await service.FinalizeFileAsync(volume, entry.FileId, new E2eeFinalizeFileRequest(encrypted.Length, 1));
        var (header, _) = _volumeService.GetMountedKeys(volume);
        header.EnsureVolumeId();
        header.AddGroupEpoch(1, []);
        await Assert.ThrowsAsync<FileServiceException>(() => service.RewrapFileKeysAsync(volume,
            new E2eeRewrapFileKeysRequest([new(entry.FileId, 1, ShapeOnlyWrappedKey())]), "testuser"));
        Assert.Equal(0, Assert.Single((await service.ListFilesAsync(volume)).Files).KeyEpoch);
        var (stream, length, revision, _) = await service.DownloadChunkAsync(volume, entry.FileId, 0);
        using (stream)
        {
            byte[] actual = new byte[length];
            await stream.ReadExactlyAsync(actual);
            Assert.Equal(expected, E2eeCrypto.DecryptChunk(actual, key, 0, salt, revision));
        }
        CryptographicOperations.ZeroMemory(key);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task UploadEncryptedBeforeRewrap_PreservesItsEncryptionEpoch(bool chunkMode, bool legacyMetadata)
    {
        _sp.GetRequiredService<IOptions<CistaNasOptions>>().Value.Storage.Provider = chunkMode ? "s3" : "local";
        string volume = await MountE2eeAsync("concurrent-epoch");
        var service = GetE2eeFileService();
        var (header, _) = _volumeService.GetMountedKeys(volume);
        string volumeId = header.EnsureVolumeId();
        header.AddGroupEpoch(1, []);
        byte[] fileKey = E2eeV2.GenerateFileKey(), group1 = E2eeV2.GenerateGroupKey(), group2 = E2eeV2.GenerateGroupKey();
        byte[] salt = E2eeV2.GenerateFileSalt();
        string fileId = Guid.NewGuid().ToString("N");
        var entry = await service.CreateFileAsync(volume,
            new E2eeCreateFileRequest("enc", 35, 1, 1, WrapForEpoch(fileKey, group1, volumeId, fileId, 1)),
            "testuser", preallocatedFileId: fileId);
        byte[] initial = E2eeV2.EncryptChunk([1, 2, 3], fileKey,
            new E2eeChunkContext(volumeId, fileId, 0, 0, 1), true, salt);
        using (var source = new MemoryStream(initial))
            await service.UploadChunkAsync(volume, fileId, 0, source, initial.Length);
        await service.FinalizeFileAsync(volume, fileId, new E2eeFinalizeFileRequest(initial.Length, 1));

        if (legacyMetadata)
        {
            var storage = _sp.GetRequiredService<IStorageProvider>();
            string path = $"{volume}/catalog-e2ee.json";
            var catalog = System.Text.Json.Nodes.JsonNode.Parse((await storage.ReadAsync(path))!)!;
            Assert.True(catalog["Files"]![fileId]!.AsObject().Remove("ChunkKeyEpochs"));
            using var saved = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(catalog.ToJsonString()));
            await storage.WriteAtomicAsync(path, saved);
        }

        // Encryption starts before another client rotates and rewraps the same DEK.
        byte[] expected = [4, 5, 6];
        byte[] replacement = E2eeV2.EncryptChunk(expected, fileKey,
            new E2eeChunkContext(volumeId, fileId, 0, 1, 1), true, salt);
        header.AddGroupEpoch(2, []);
        await service.RewrapFileKeysAsync(volume,
            new E2eeRewrapFileKeysRequest([new(fileId, 2, WrapForEpoch(fileKey, group2, volumeId, fileId, 2))]), "testuser");
        // Older catalogs rely on the file's epoch when chunk epochs are absent.
        // Preserve that effective epoch before changing the file's wrap epoch.
        var (oldStream, oldLength, oldRevision, oldEpoch) = await service.DownloadChunkAsync(volume, fileId, 0);
        using (oldStream)
        {
            byte[] original = new byte[oldLength];
            await oldStream.ReadExactlyAsync(original);
            Assert.Equal(new byte[] { 1, 2, 3 }, E2eeV2.DecryptChunk(original, fileKey,
                new E2eeChunkContext(volumeId, fileId, 0, oldRevision, oldEpoch), salt));
        }
        Assert.Equal(StatusCodes.Status200OK, await UploadThroughEpochApiAsync(service, volume, fileId, replacement, "1"));
        await service.FinalizeFileAsync(volume, fileId, new E2eeFinalizeFileRequest(replacement.Length, 1));
        var (stream, length, revision, epoch) = await service.DownloadChunkAsync(volume, fileId, 0);
        using (stream)
        {
            byte[] actual = new byte[length];
            await stream.ReadExactlyAsync(actual);
            Assert.Equal(expected, E2eeV2.DecryptChunk(actual, fileKey,
                new E2eeChunkContext(volumeId, fileId, 0, revision, epoch), salt));
        }
        Assert.Equal(1, epoch);
        Assert.Equal(2, Assert.Single((await service.ListFilesAsync(volume)).Files).KeyEpoch);
        CryptographicOperations.ZeroMemory(fileKey);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("0")]
    [InlineData("99")]
    [InlineData("invalid")]
    [InlineData("1,2")]
    public async Task InvalidUploadEpoch_IsRejectedBeforeReplacingStoredBytes(string? epoch)
    {
        string volume = await MountE2eeAsync("bad-upload-epoch");
        var (header, _) = _volumeService.GetMountedKeys(volume);
        header.EnsureVolumeId();
        header.AddGroupEpoch(1, []);
        var service = GetE2eeFileService();
        var entry = await service.CreateFileAsync(volume, new E2eeCreateFileRequest("enc", 35, 1, 1, ShapeOnlyWrappedKey()), "testuser");
        byte[] original = Enumerable.Repeat((byte)42, 35).ToArray();
        using (var source = new MemoryStream(original))
            await service.UploadChunkAsync(volume, entry.FileId, 0, source, original.Length);
        Assert.Equal(StatusCodes.Status400BadRequest,
            await UploadThroughEpochApiAsync(service, volume, entry.FileId, new byte[35], epoch));
        var (stream, length, _, _) = await service.DownloadChunkAsync(volume, entry.FileId, 0);
        using (stream)
        {
            byte[] actual = new byte[length];
            await stream.ReadExactlyAsync(actual);
            Assert.Equal(original, actual);
        }
    }

    private async Task<int?> UploadThroughEpochApiAsync(E2eeFileService service, string volume, string fileId,
        byte[] bytes, string? epoch)
    {
        var leases = new E2eeWriteLeaseService(_sp.GetRequiredService<IStorageProvider>());
        var lease = await leases.AcquireAsync(volume, fileId);
        try
        {
            var ctx = new DefaultHttpContext();
            using var body = new MemoryStream(bytes);
            ctx.Request.Body = body;
            ctx.Request.ContentLength = bytes.Length;
            ctx.Request.Headers[E2eeWriteLeaseService.HeaderName] = lease.Token;
            if (epoch is not null) ctx.Request.Headers["X-Chunk-KeyEpoch"] = epoch;
            var result = await InvokeEpochUploadEndpointAsync(service, volume, fileId, leases, ctx.Request);
            return ((IStatusCodeHttpResult)result).StatusCode;
        }
        finally { await leases.ReleaseAsync(volume, fileId, lease.Token); }
    }

    private Task<IResult> InvokeEpochUploadEndpointAsync(E2eeFileService service, string volume, string fileId,
        E2eeWriteLeaseService leases, HttpRequest request)
    {
        var method = typeof(E2eeEndpoints).GetMethod("UploadChunk", BindingFlags.Static | BindingFlags.NonPublic)!;
        return (Task<IResult>)method.Invoke(null, [volume, fileId, 0, request, _volumeService, service, leases, true])!;
    }

    private static VolumeHeader.WrappedKey ShapeOnlyWrappedKey() => new()
    { Nonce = new byte[12], Ciphertext = new byte[32], Tag = new byte[16] };

    private static VolumeHeader.WrappedKey WrapForEpoch(byte[] fileKey, byte[] groupKey, string volumeId, string fileId, int epoch)
    {
        var (nonce, ciphertext, tag) = E2eeV2.WrapFileKey(fileKey, groupKey, volumeId, fileId, epoch);
        return new() { Nonce = nonce, Ciphertext = ciphertext, Tag = tag };
    }
}
