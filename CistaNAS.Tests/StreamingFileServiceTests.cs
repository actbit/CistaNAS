using System.Reflection;
using System.Security.Cryptography;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Tests;

public sealed class StreamingFileServiceTests
{
    [Theory]
    [InlineData(200, 0, 2)]
    [InlineData(206, 1, 2)]
    [InlineData(206, 0, 3)]
    [InlineData(206, 0, 1)]
    public async Task ServerRange_IgnoredWrongOversizedOrTruncatedResponse_IsRejected(int status, long start, int length)
    {
        using var http = new HttpClient(new ResponseHandler(request =>
        {
            var response = new HttpResponseMessage((HttpStatusCode)status) { Content = new ByteArrayContent(new byte[length]) };
            response.Content.Headers.ContentRange = new System.Net.Http.Headers.ContentRangeHeaderValue(start, start + 1, 10);
            return response;
        })) { BaseAddress = new Uri("http://test/") };
        using var session = new E2eeSession();
        using var content = new StreamingFileService(new CistaNasApiClient(http), session)
            .OpenServerFile("vol", "clip.mp4", new FileMetadata { Name = "clip.mp4", Length = 10 }, default);
        byte[] buffer = [42, 42];
        var error = await Record.ExceptionAsync(() => content.ReadAsync(0, buffer).AsTask());
        Assert.True(error is InvalidDataException or EndOfStreamException);
        Assert.All(buffer, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task OversizedEncryptedChunk_IsRejectedBeforeBodyRead()
    {
        using var http = new HttpClient(new ResponseHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StreamContent(new OversizedBody()) })) { BaseAddress = new Uri("http://test/") };
        using var session = new E2eeSession();
        session.StoreKey("vol", E2eeCrypto.GenerateMasterKey(), 1024);
        var entry = new E2eeFileEntry { FileId = "id", EncryptedName = "", ChunkCount = 1,
            EncryptedLength = E2eeCrypto.ComputeEncryptedLength(1, 1024) };
        await Assert.ThrowsAsync<InvalidDataException>(() => new StreamingFileService(new CistaNasApiClient(http), session)
            .OpenE2eeFileAsync("vol", "clip.mp4", entry));
    }

    [Theory]
    [InlineData(false, 0)]
    [InlineData(false, 100000)]
    [InlineData(true, 0)]
    [InlineData(true, 100000)]
    public async Task RandomSeekAndChunkBoundaries_ReturnOriginalBytes_WithOneChunkInRam(bool v2, int length)
    {
        using var server = new FakeE2eeServer();
        using var http = new HttpClient(server) { BaseAddress = new Uri("http://test/") };
        using var session = new E2eeSession();
        session.StoreKey("vol", E2eeCrypto.GenerateMasterKey(), 1024);
        if (v2) session.StoreV2State("vol", Guid.NewGuid().ToString("N"),
            new Dictionary<int, byte[]> { [1] = E2eeV2.GenerateGroupKey() });
        var api = new CistaNasApiClient(http);
        var original = RandomNumberGenerator.GetBytes(length);
        using var input = new MemoryStream(original);
        await new E2eeFileTransferService(api, session).UploadAsync("vol", "clip.mp4", input, length);
        using var content = await new StreamingFileService(api, session).OpenE2eeFileAsync("vol", "clip.mp4", server.LastCreated!);
        Assert.Equal(length, content.Length);
        Assert.Equal(new[] { 0 }, server.DownloadRequests);
        var plainField = content.GetType().GetField("_plain", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var first = (byte[])plainField.GetValue(content)!;
        foreach (long offset in new long[] { 50000, 1020, 0, Math.Max(0, length - 3), length, length + 1 })
        {
            byte[] result = new byte[ReadOnlyFileContent.MaxReadBytes * 2];
            int count = await content.ReadAsync(offset, result);
            int expected = (int)Math.Min(ReadOnlyFileContent.MaxReadBytes, Math.Max(0, length - offset));
            Assert.Equal(expected, count);
            Assert.Equal(original.Skip((int)offset).Take(count), result.Take(count));
            Assert.All(result.Skip(count), b => Assert.Equal(0, b));
            Assert.InRange(((byte[])plainField.GetValue(content)!).Length, 0, 1024);
        }
        if (length > 0) Assert.All(first, b => Assert.Equal(0, b));
        var retained = (byte[])plainField.GetValue(content)!;
        content.Dispose();
        Assert.All(retained, b => Assert.Equal(0, b));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => content.ReadAsync(0, new byte[1]).AsTask());
    }

    [Fact]
    public async Task SeekToEditedV1Chunk_UsesReturnedRevision()
    {
        using var server = new FakeE2eeServer();
        using var http = new HttpClient(server) { BaseAddress = new Uri("http://test/") };
        using var session = new E2eeSession();
        byte[] master = E2eeCrypto.GenerateMasterKey();
        session.StoreKey("vol", master, 1024);
        byte[] salt = E2eeCrypto.GenerateFileSalt();
        byte[] key = E2eeCrypto.DeriveFileKey(master, salt);
        byte[] first = RandomNumberGenerator.GetBytes(1024);
        byte[] tail = RandomNumberGenerator.GetBytes(100);
        string id = server.SeedFile((0, E2eeCrypto.EncryptChunk(first, key, 0, salt, isFirstChunk: true), 0),
            (1, E2eeCrypto.EncryptChunk(tail, key, 1, salt, isFirstChunk: false, revision: 7), 7));
        var entry = new E2eeFileEntry { FileId = id, EncryptedName = "", ChunkCount = 2,
            EncryptedLength = E2eeCrypto.ComputeEncryptedLength(1124, 1024) };
        using var content = await new StreamingFileService(new CistaNasApiClient(http), session).OpenE2eeFileAsync("vol", "clip.mp4", entry);
        byte[] actual = new byte[100];
        Assert.Equal(100, await content.ReadAsync(1024, actual));
        Assert.Equal(tail, actual);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TamperedLaterChunk_FailsAndWipesPartialRead(bool v2)
    {
        using var server = new FakeE2eeServer();
        using var http = new HttpClient(server) { BaseAddress = new Uri("http://test/") };
        using var session = new E2eeSession();
        session.StoreKey("vol", E2eeCrypto.GenerateMasterKey(), 1024);
        if (v2) session.StoreV2State("vol", Guid.NewGuid().ToString("N"),
            new Dictionary<int, byte[]> { [1] = E2eeV2.GenerateGroupKey() });
        var api = new CistaNasApiClient(http);
        using var input = new MemoryStream(RandomNumberGenerator.GetBytes(3000));
        await new E2eeFileTransferService(api, session).UploadAsync("vol", "clip.mp4", input, input.Length);
        using var content = await new StreamingFileService(api, session).OpenE2eeFileAsync("vol", "clip.mp4", server.LastCreated!);
        server.CorruptChunk(server.LastCreated!.FileId, 1);
        byte[] result = Enumerable.Repeat((byte)42, 100).ToArray();
        await Assert.ThrowsAnyAsync<CryptographicException>(() => content.ReadAsync(1000, result).AsTask());
        Assert.All(result, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task RegistryCloseAndClear_DisposeAndZeroContent()
    {
        var registry = new StreamingFileRegistry();
        var first = new MemoryContent(new byte[] { 1, 2, 3 });
        var second = new MemoryContent(new byte[] { 4, 5, 6 });
        string id = registry.Add(first);
        registry.Add(second);
        registry.Remove(id);
        Assert.Throws<FileNotFoundException>(() => registry.Get(id));
        Assert.All(first.Bytes, b => Assert.Equal(0, b));
        registry.Clear();
        Assert.All(second.Bytes, b => Assert.Equal(0, b));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => second.ReadAsync(0, new byte[3]).AsTask());
    }

    private sealed class MemoryContent(byte[] bytes) : ReadOnlyFileContent("clip.mp4", bytes.Length, default)
    {
        public byte[] Bytes => bytes;
        protected override ValueTask<int> ReadCoreAsync(long offset, Memory<byte> destination, CancellationToken ct)
        { bytes.AsMemory((int)offset, destination.Length).CopyTo(destination); return ValueTask.FromResult(destination.Length); }
        protected override void ClearBuffers() => CryptographicOperations.ZeroMemory(bytes);
    }

    private sealed class ResponseHandler(Func<HttpRequestMessage, HttpResponseMessage> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => Task.FromResult(send(request));
    }
    private sealed class OversizedBody : MemoryStream
    {
        public override long Length => 10000000;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => throw new InvalidOperationException("Body must not be read");
    }
}
