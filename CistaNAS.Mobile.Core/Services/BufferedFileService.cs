using System.Security.Cryptography;
using CistaNAS.Client.Api;

namespace CistaNAS.Mobile.Core.Services;

/// <summary>画像・テキストの必要量だけを、範囲検証付きで所有するRAMバッファへ読み込む。</summary>
public sealed class BufferedFileService(StreamingFileService files)
{
    public const int ImageLimit = 32 * 1024 * 1024;
    public const int TextLimit = 2 * 1024 * 1024;

    public async Task<byte[]> ReadAsync(string volume, string name, string path, bool e2ee,
        FileMetadata? metadata, E2eeFileEntry? entry, int limit, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        long length = e2ee
            ? E2eeFileTransferService.ComputePlainLength(entry ?? throw new InvalidDataException("ファイル情報がありません。"))
            : (metadata ?? throw new InvalidDataException("ファイル情報がありません。")).Length;
        if (length < 0 || length > limit)
            throw new InvalidDataException($"表示できるサイズの上限は {limit / 1024 / 1024} MiB です。");
        using var content = e2ee
            ? await files.OpenE2eeFileAsync(volume, name, entry!, ct).ConfigureAwait(false)
            : files.OpenServerFile(volume, path, metadata!, ct);
        byte[] result = new byte[checked((int)length)];
        try
        {
            int offset = 0;
            while (offset < result.Length)
            {
                int read = await content.ReadAsync(offset, result.AsMemory(offset), ct).ConfigureAwait(false);
                if (read == 0) throw new EndOfStreamException("ファイルの読み取りが途中で終了しました。");
                offset += read;
            }
            ct.ThrowIfCancellationRequested();
            return result;
        }
        catch { CryptographicOperations.ZeroMemory(result); throw; }
    }
}
