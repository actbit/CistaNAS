using System.Text.Json;
using CistaNAS.Shared.Crypto;
using CistaNAS.Wasm.Services;
using Microsoft.JSInterop;

namespace CistaNAS.Tests;

public sealed class WasmUploadIntegrityTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellationAfterLastChunk_DoesNotFinalizeUpload(bool v2)
    {
        using var server = new UploadServer();
        using var http = new HttpClient(server) { BaseAddress = new Uri("http://test/") };
        await using var crypto = new E2eeInterop(new FakeCrypto());
        var transfer = new CistaNAS.Wasm.Services.E2eeFileTransferService(new E2eeApiClient(http), crypto);
        using var stop = new CancellationTokenSource();
        using var source = new MemoryStream(new byte[3]);
        var progress = new CancelProgress(stop);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => v2
            ? transfer.UploadV2Async("vol", "file.bin", source, 3, 1024, new E2eeV2KeyContext("volume", 1, Convert.ToBase64String(new byte[32])), progress, stop.Token)
            : transfer.UploadAsync("vol", "file.bin", source, 3, 1024, "master", progress, stop.Token));
        Assert.Equal(0, server.Finalized);
        Assert.Equal(1, server.Deleted);
        Assert.Equal(1, server.Released);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UploadHonorsDeclaredLength_AndWipesSourceBuffers(bool v2)
    {
        using var server = new UploadServer();
        using var http = new HttpClient(server) { BaseAddress = new Uri("http://test/") };
        await using var crypto = new E2eeInterop(new FakeCrypto());
        var transfer = new CistaNAS.Wasm.Services.E2eeFileTransferService(new E2eeApiClient(http), crypto);
        using var source = new RetainingSource(Enumerable.Repeat((byte)9, 1501).ToArray());
        if (v2) await transfer.UploadV2Async("vol", "file.bin", source, 1500, 1024, new E2eeV2KeyContext("volume", 1, Convert.ToBase64String(new byte[32])));
        else await transfer.UploadAsync("vol", "file.bin", source, 1500, 1024, "master");
        Assert.Equal(1500, source.Position);
        Assert.Equal(1, server.Finalized);
        Assert.Equal(0, server.Deleted);
        Assert.Equal(1, server.Released);
        Assert.NotEmpty(source.Buffers);
        foreach (byte[] buffer in source.Buffers) Assert.All(buffer, b => Assert.Equal(0, b));
    }

    private sealed class RetainingSource(byte[] bytes) : MemoryStream(bytes)
    {
        public List<byte[]> Buffers { get; } = [];
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            Assert.True(System.Runtime.InteropServices.MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment));
            Buffers.Add(segment.Array!);
            return base.ReadAsync(buffer, ct);
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        { Buffers.Add(buffer); return base.ReadAsync(buffer, offset, count, ct); }
    }
    private sealed class CancelProgress(CancellationTokenSource stop) : IProgress<double>
    { public void Report(double value) { if (value == 100) stop.Cancel(); } }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShortSource_IsRejectedAndRolledBackInsteadOfSavingTruncatedFile(bool v2)
    {
        using var server = new UploadServer();
        using var http = new HttpClient(server) { BaseAddress = new Uri("http://test/") };
        await using var crypto = new E2eeInterop(new FakeCrypto());
        var transfer = new CistaNAS.Wasm.Services.E2eeFileTransferService(new E2eeApiClient(http), crypto);
        using var source = new MemoryStream(new byte[1499]);
        await Assert.ThrowsAsync<EndOfStreamException>(() => v2
            ? transfer.UploadV2Async("vol", "file.bin", source, 1500, 1024, new E2eeV2KeyContext("volume", 1, Convert.ToBase64String(new byte[32])))
            : transfer.UploadAsync("vol", "file.bin", source, 1500, 1024, "master"));
        Assert.Equal(0, server.Finalized);
        Assert.Equal(1, server.Deleted);
        Assert.Equal(1, server.Released);
    }

    private sealed class UploadServer : HttpMessageHandler
    {
        public int Finalized, Deleted, Released;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("create-file"))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Created)
                { Content = new StringContent("{\"fileId\":\"file\",\"encryptedName\":\"name\",\"writeLeaseToken\":\"lease\"}", System.Text.Encoding.UTF8, "application/json") });
            if (path.Contains("finalize-file")) Finalized++;
            if (request.Method == HttpMethod.Delete)
            { if (path.EndsWith("write-lease")) Released++; else Deleted++; }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
        }
    }

    private sealed class FakeCrypto : IJSRuntime, IJSObjectReference
    {
        public ValueTask<T> InvokeAsync<T>(string identifier, object?[]? args) => InvokeAsync<T>(identifier, default, args);
        public ValueTask<T> InvokeAsync<T>(string identifier, CancellationToken ct, object?[]? args)
        {
            object? result = identifier switch
            {
                "import" => this,
                "encryptFilename" or "importKeyHandleFromB64" => "key",
                "generateFileSalt" => Convert.ToBase64String(new byte[16]),
                "generateFileKeyV2" => Convert.ToBase64String(new byte[32]),
                "wrapFileKey" => JsonSerializer.SerializeToElement(new
                { nonce = Convert.ToBase64String(new byte[12]), ciphertext = Convert.ToBase64String(new byte[32]), tag = Convert.ToBase64String(new byte[16]) }),
                "encryptChunk" or "encryptChunkV2" => Convert.ToBase64String(new byte[Convert.FromBase64String((string)args![0]!).Length + E2eeCrypto.GcmTagSize]),
                "clearKey" => default(T),
                _ => throw new InvalidOperationException(identifier)
            };
            return ValueTask.FromResult((T)result!);
        }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
