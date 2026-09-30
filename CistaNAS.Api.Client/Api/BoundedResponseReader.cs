using System.Security.Cryptography;

namespace CistaNAS.Client.Api;

internal static class BoundedResponseReader
{
    public static async Task<byte[]> ReadAsync(HttpContent content, int limit, CancellationToken ct)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limit);
        if (content.Headers.ContentLength > limit) throw new InvalidDataException("読み取り上限を超える応答です。");
        byte[] bytes = new byte[limit];
        try
        {
            using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            int read = await stream.ReadAtLeastAsync(bytes, limit, throwOnEndOfStream: false, ct).ConfigureAwait(false);
            byte[] extra = new byte[1];
            try
            {
                if (await stream.ReadAsync(extra, ct).ConfigureAwait(false) != 0)
                    throw new InvalidDataException("読み取り上限を超える応答です。");
            }
            finally { CryptographicOperations.ZeroMemory(extra); }
            if (read == limit) return bytes;
            byte[] partial = bytes[..read];
            CryptographicOperations.ZeroMemory(bytes);
            return partial;
        }
        catch { CryptographicOperations.ZeroMemory(bytes); throw; }
    }
}
