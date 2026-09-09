using CistaNAS.Wasm.Models;
using Microsoft.JSInterop;

namespace CistaNAS.Wasm.Services;

/// <summary>共有 E2EE v2（GroupKey epoch モード）のアップロード用鍵コンテキスト。</summary>
/// <param name="VolumeId">ボリュームヘッダの VolumeId（GUID "N"。AAD bind 用）。</param>
/// <param name="KeyEpoch">書き込み先の GroupKey epoch（サーバー現行 epoch と一致させる）。</param>
/// <param name="GroupKeyB64">現行 epoch の GroupKey（base64 32B）。</param>
public sealed record E2eeV2KeyContext(string VolumeId, int KeyEpoch, string GroupKeyB64);

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
            (byte[] encData, int revision, _) = await api.DownloadChunkAsync(volumeName, fileId, i);

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

        return CombineChunks(decryptedChunks);
    }

    // ---- crypto format v2（共有 GroupKey epoch / per-file DEK）----

    /// <summary>
    /// crypto format v2 でファイルをアップロードする（共有 GroupKey epoch モード）。
    /// per-file DEK (32B CSPRNG) を生成して GroupKey[epoch] でラップし、create-file に渡す。
    /// ファイル名も GroupKey で暗号化する（v2 メンバーは masterKey を持たない）。
    /// チャンク AAD には volumeId/fileId/chunkIndex/revision/keyEpoch が bind される。
    /// </summary>
    public async Task<E2eeFileEntry> UploadV2Async(string volumeName, string fileName, Stream content,
        long totalSize, int chunkSize, E2eeV2KeyContext keyContext)
    {
        string fileKeyB64 = await e2ee.GenerateFileKeyV2();
        string groupKeyHandle = await e2ee.ImportKeyHandleFromB64(keyContext.GroupKeyB64);
        string encName;
        try
        {
            encName = await e2ee.EncryptFilename(fileName, groupKeyHandle);
        }
        finally
        {
            await e2ee.ClearKey(groupKeyHandle);
        }
        string fileSaltB64 = await e2ee.GenerateFileSalt();

        int totalChunks = (int)((totalSize + chunkSize - 1) / chunkSize);
        if (totalChunks == 0) totalChunks = 1;
        long estimatedLength = ComputeEncryptedLength(totalSize, chunkSize);

        // WrappedFileKey の AAD に fileId が bind されるため、fileId をクライアント側で
        // 確定させてから 1 リクエストで create-file する（カタログ状態を一貫させる）。
        string fileId = Guid.NewGuid().ToString("N");
        (string wNonce, string wCt, string wTag) = await e2ee.WrapFileKey(
            fileKeyB64, keyContext.GroupKeyB64, keyContext.VolumeId, fileId, keyContext.KeyEpoch);
        var wrappedFileKey = new WrappedAeadKeyParams
        {
            Algorithm = "aes-256-gcm",
            Nonce = Convert.FromBase64String(wNonce),
            Ciphertext = Convert.FromBase64String(wCt),
            Tag = Convert.FromBase64String(wTag),
        };

        var entry = await api.CreateFileAsync(volumeName, encName, estimatedLength, totalChunks,
            keyContext.KeyEpoch, wrappedFileKey, fileId);
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

                string encB64 = await e2ee.EncryptChunkV2(buffer, fileKeyB64, i,
                    revision: 0, keyContext.KeyEpoch, keyContext.VolumeId, entry.FileId,
                    fileSaltB64, isFirstChunk: i == 0);
                byte[] encBytes = Convert.FromBase64String(encB64);

                await api.UploadChunkAsync(volumeName, entry.FileId, i, encBytes, writeLease);
                bytesRemaining -= read;
            }

            await api.FinalizeFileAsync(volumeName, entry.FileId,
                ComputeEncryptedLength(totalSize - bytesRemaining, chunkSize), writeLease);
            return entry;
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

    /// <summary>crypto format v2 ファイルをダウンロードして復号する。
    /// GroupKey は epoch → base64 の辞書で渡す（旧 epoch ファイルは旧 epoch GroupKey で復号）。
    /// v1 ファイル（KeyEpoch == 0）は masterKey 版 <see cref="DownloadAsync(string,string,int,string)"/> を使用。</summary>
    public async Task<byte[]> DownloadAsync(string volumeName, E2eeFileEntry entry, string volumeId,
        IReadOnlyDictionary<int, string> groupKeysByEpoch)
    {
        string fileKeyB64 = await UnwrapFileKeyAsync(volumeId, entry, groupKeysByEpoch);
        var decryptedChunks = new List<byte[]>(entry.ChunkCount);
        string? fileSaltB64 = null;

        for (int i = 0; i < entry.ChunkCount; i++)
        {
            (byte[] encData, int revision, int chunkEpoch) = await api.DownloadChunkAsync(volumeName, entry.FileId, i);

            if (i == 0 && fileSaltB64 is null)
            {
                byte[] salt = new byte[16];
                Buffer.BlockCopy(encData, 0, salt, 0, 16);
                fileSaltB64 = Convert.ToBase64String(salt);
            }

            string encB64 = Convert.ToBase64String(encData);
            // チャンクの nonce / AAD は暗号化時の keyEpoch を bind するため、
            // サーバーがチャンクごとに返す epoch を使う（旧サーバー / ヘッダ欠如時は entry.KeyEpoch）。
            decryptedChunks.Add(await e2ee.DecryptChunkV2(encB64, fileKeyB64, i, revision,
                chunkEpoch > 0 ? chunkEpoch : entry.KeyEpoch, volumeId, entry.FileId, fileSaltB64 ?? ""));
        }

        return CombineChunks(decryptedChunks);
    }

    /// <summary>v2: WrappedFileKey を GroupKey[entry.KeyEpoch] でアンラップして per-file DEK (base64) を返す。</summary>
    public async Task<string> UnwrapFileKeyAsync(string volumeId, E2eeFileEntry entry,
        IReadOnlyDictionary<int, string> groupKeysByEpoch)
    {
        if (!groupKeysByEpoch.TryGetValue(entry.KeyEpoch, out string? groupKeyB64))
            throw new InvalidOperationException(
                $"GroupKey epoch {entry.KeyEpoch} が利用できません（このファイルを読む権限がない可能性があります）。");
        var wfk = entry.WrappedFileKey
            ?? throw new InvalidOperationException($"ファイル '{entry.FileId}' に WrappedFileKey がありません。");
        return await e2ee.UnwrapFileKey(
            Convert.ToBase64String(wfk.Nonce), Convert.ToBase64String(wfk.Ciphertext), Convert.ToBase64String(wfk.Tag),
            groupKeyB64, volumeId, entry.FileId, entry.KeyEpoch);
    }

    /// <summary>
    /// v2: ファイル名を GroupKey で復号する（v1 ファイルは masterKey 版を使用）。
    /// ファイル名はアップロード時点の epoch の GroupKey で暗号化され、rotation + rewrap では
    /// 再暗号化されないため、まず entry.KeyEpoch で試し、失敗したら保持する他の epoch にフォールバックする
    /// （旧 epoch 鍵は旧ファイル readable 維持のために保持されている）。
    /// </summary>
    public async Task<string> DecryptFilenameV2Async(E2eeFileEntry entry, string volumeId,
        IReadOnlyDictionary<int, string> groupKeysByEpoch)
    {
        if (groupKeysByEpoch.TryGetValue(entry.KeyEpoch, out string? groupKeyB64))
        {
            string handle = await e2ee.ImportKeyHandleFromB64(groupKeyB64);
            try
            {
                return await e2ee.DecryptFilename(entry.EncryptedName, handle);
            }
            catch (JSException) { /* 旧 epoch の鍵で暗号化された可能性 → フォールバック */ }
            finally
            {
                await e2ee.ClearKey(handle);
            }
        }

        foreach (var (epoch, keyB64) in groupKeysByEpoch.OrderByDescending(kv => kv.Key))
        {
            if (epoch == entry.KeyEpoch) continue;
            string handle = await e2ee.ImportKeyHandleFromB64(keyB64);
            try
            {
                return await e2ee.DecryptFilename(entry.EncryptedName, handle);
            }
            catch (JSException) { /* 次の epoch を試す */ }
            finally
            {
                await e2ee.ClearKey(handle);
            }
        }
        throw new InvalidOperationException(
            $"ファイル名を復号できる GroupKey がありません（epoch {entry.KeyEpoch}。このファイルを読む権限がない可能性があります）。");
    }

    private static byte[] CombineChunks(List<byte[]> decryptedChunks)
    {
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
