using CistaNAS.Wasm.Models;

namespace CistaNAS.Wasm.Services;

/// <summary>
/// E2EE ファイルの転送オーケストレーション（アップロード / ダウンロード / 削除）。
/// 書き込みリースの取得・更新・解放やロールバックなどビジネスロジックを担当し、
/// Blazor Pages からは委譲して使う（CLAUDE.md のレイヤー規約）。
/// 暗号化プリミティブはブラウザ側 JS（<see cref="E2eeInterop"/>）で実行する。
/// </summary>
public sealed class E2eeFileTransferService(E2eeApiClient api, E2eeInterop e2ee)
{
    /// <summary>E2EE ファイルをチャンク暗号化しながらアップロードする。
    /// 失敗時は作成済みの fileId をロールバック削除し、リースを確実に解放する。</summary>
    public async Task UploadAsync(string volumeName, string fileName, Stream content,
        long totalSize, int chunkSize, string masterKeyHandle)
    {
        string encName = await e2ee.EncryptFilename(fileName, masterKeyHandle);
        string fileSaltB64 = await e2ee.GenerateFileSalt();

        int totalChunks = (int)((totalSize + chunkSize - 1) / chunkSize);
        if (totalChunks == 0) totalChunks = 1;

        // 暗号化後サイズの推定 (salt 16 bytes + chunk ごとに tag 16 bytes)
        long estimatedLength = ComputeEncryptedLength(totalSize, chunkSize);

        var entry = await api.CreateFileAsync(volumeName, encName, estimatedLength, totalChunks);
        string writeLease = entry.WriteLeaseToken
            ?? throw new InvalidDataException("書き込みリースtokenがありません。");
        try
        {
            long bytesRemaining = totalSize;
            for (int i = 0; i < totalChunks; i++)
            {
                int readLen = (int)Math.Min(chunkSize, bytesRemaining);
                byte[] buffer = new byte[readLen];
                int read = 0;
                while (read < readLen)
                {
                    int n = await content.ReadAsync(buffer, read, readLen - read);
                    if (n == 0) break;
                    read += n;
                }
                if (read < buffer.Length) buffer = buffer[..read];

                string encB64 = await e2ee.EncryptChunk(buffer, masterKeyHandle, i, fileSaltB64, isFirstChunk: i == 0);
                byte[] encBytes = Convert.FromBase64String(encB64);

                await api.UploadChunkAsync(volumeName, entry.FileId, i, encBytes, writeLease);
                bytesRemaining -= read;
            }

            await api.FinalizeFileAsync(volumeName, entry.FileId,
                ComputeEncryptedLength(totalSize - bytesRemaining, chunkSize), writeLease);
        }
        catch
        {
            try { await api.DeleteFileAsync(volumeName, entry.FileId, writeLease); }
            catch { }
            throw;
        }
        finally
        {
            try { await api.ReleaseWriteLeaseAsync(volumeName, entry.FileId, writeLease); }
            catch { }
        }
    }

    /// <summary>E2EE ファイルを全チャンクダウンロードして復号・結合した平文を返す。
    /// Dokan 差分保存で再暗号化されたチャンク (revision >= 1) にも対応。</summary>
    public async Task<byte[]> DownloadAsync(string volumeName, string fileId,
        int chunkCount, string masterKeyHandle)
    {
        var decryptedChunks = new List<byte[]>(chunkCount);
        string? fileSaltB64 = null;

        for (int i = 0; i < chunkCount; i++)
        {
            (byte[] encData, int revision) = await api.DownloadChunkAsync(volumeName, fileId, i);

            if (i == 0 && fileSaltB64 is null)
            {
                byte[] salt = new byte[16];
                Buffer.BlockCopy(encData, 0, salt, 0, 16);
                fileSaltB64 = Convert.ToBase64String(salt);
            }

            string encB64 = Convert.ToBase64String(encData);
            // revision >= 1 のチャンク（Dokan 差分保存で再暗号化済み）は nonce 導出に revision が必須
            decryptedChunks.Add(await e2ee.DecryptChunk(encB64, masterKeyHandle, i, fileSaltB64 ?? "", revision));
        }

        int totalLength = 0;
        foreach (var chunk in decryptedChunks) totalLength += chunk.Length;

        byte[] combined = new byte[totalLength];
        int offset = 0;
        foreach (var chunk in decryptedChunks)
        {
            Buffer.BlockCopy(chunk, 0, combined, offset, chunk.Length);
            offset += chunk.Length;
        }
        return combined;
    }

    /// <summary>E2EE ファイルを削除する（書き込みリース取得 → 削除 → リース解放）。</summary>
    public async Task DeleteAsync(string volumeName, string fileId)
    {
        string writeLease = await api.AcquireWriteLeaseAsync(volumeName, fileId);
        try
        {
            await api.DeleteFileAsync(volumeName, fileId, writeLease);
        }
        finally
        {
            try { await api.ReleaseWriteLeaseAsync(volumeName, fileId, writeLease); }
            catch { }
        }
    }

    /// <summary>暗号化後サイズの推定 (salt 16 bytes + chunk ごとに tag 16 bytes)。</summary>
    public static long ComputeEncryptedLength(long plainSize, int chunkSize)
    {
        int totalChunks = Math.Max(1, (int)((plainSize + chunkSize - 1) / chunkSize));
        return plainSize + 16 + (long)totalChunks * 16;
    }
}
