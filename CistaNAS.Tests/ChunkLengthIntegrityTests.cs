using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;
using CistaNAS.Tests.Helpers;
using CistaNAS.Web.Services;

namespace CistaNAS.Tests;

public sealed class ChunkLengthIntegrityTests
{
    [Theory]
    [InlineData(CipherAlgorithm.Aes256Xts)]
    [InlineData(CipherAlgorithm.ChaCha20)]
    public async Task OverlongEncryptedChunk_IsRejectedByDownload(CipherAlgorithm algorithm)
    {
        byte[] key = RandomNumberGenerator.GetBytes(algorithm == CipherAlgorithm.Aes256Xts ? 64 : 32);
        byte[] stored = ChunkEncryptor.EncryptChunk(key, algorithm, 0, 512, 4096, new byte[48]);
        var store = new InMemoryChunkStore();
        await store.WriteChunkAsync("vol", "file", 0, new MemoryStream(stored));
        using var stream = new ChunkedReadStream(store, "vol", "file", key, algorithm, 512, 4096, [17]);

        await Assert.ThrowsAsync<InvalidDataException>(() => stream.ReadAsync(new byte[17]).AsTask());
        Assert.Equal(0, stream.Position);
    }

    [Theory]
    [InlineData(CipherAlgorithm.Aes256Xts)]
    [InlineData(CipherAlgorithm.ChaCha20)]
    public void TruncatedEncryptedChunk_IsRejectedBeforeReturningPlaintext(CipherAlgorithm algorithm)
    {
        byte[] key = RandomNumberGenerator.GetBytes(algorithm == CipherAlgorithm.Aes256Xts ? 64 : 32);
        byte[] stored = ChunkEncryptor.EncryptChunk(key, algorithm, 0, 512, 4096, new byte[48]);
        Array.Resize(ref stored, stored.Length - 16);

        Assert.Throws<InvalidDataException>(() =>
            ChunkEncryptor.DecryptChunk(key, algorithm, 0, 512, 4096, stored, 48));
    }
}
