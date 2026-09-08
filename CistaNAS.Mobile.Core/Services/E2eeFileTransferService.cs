using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Mobile.Core.Services;

/// <summary>
/// E2EE ボリュームのファイル転送 (チャンク暗号化 / 復号 + write-lease 制御)。
/// 暗号化プロトコルは Shared.E2eeCrypto (WASM e2ee.js と相互運用) に一本化。
/// </summary>
public sealed class E2eeFileTransferService(CistaNasApiClient api, E2eeSession e2eeSession)
{
    /// <summary>メモリ上での復号サイズ上限。超えるファイルはキャッシュファイル経由にフォールバック。</summary>
    public const long MaxInMemoryDownloadBytes = 50 * 1024 * 1024;

    /// <summary>
    /// E2EE ファイルを復号しながら <paramref name="output"/> へダウンロードする。
    /// チャンク 0 の先頭 16B (fileSalt) から fileKey を導出する。
    /// </summary>
    public async Task DownloadAsync(string volumeName, E2eeFileEntry entry, Stream output,
        IProgress<double>? progress = null, CancellationToken ct = default)
    {
        byte[] masterKey = e2eeSession.GetMasterKey(volumeName);
        int chunkSize = e2eeSession.GetChunkSize(volumeName);

        // チャンク 0 から fileSalt を取得して fileKey を導出
        (byte[] data0, int revision0) = await api.DownloadChunkAsync(volumeName, entry.FileId, 0);
        if (data0.Length < E2eeCrypto.SaltSize + E2eeCrypto.GcmTagSize)
            throw new InvalidOperationException("チャンク 0 が不正です。");
        byte[] fileSalt = new byte[E2eeCrypto.SaltSize];
        Buffer.BlockCopy(data0, 0, fileSalt, 0, E2eeCrypto.SaltSize);
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);

        // nonce 導出にはチャンクごとの revision が必須（Dokan 差分保存で revision >= 1 に上がる）。
        byte[] plain0 = E2eeCrypto.DecryptChunk(data0, fileKey, 0, fileSalt, revision0);
        await output.WriteAsync(plain0, ct);

        for (int i = 1; i < entry.ChunkCount; i++)
        {
            ct.ThrowIfCancellationRequested();
            (byte[] enc, int revision) = await api.DownloadChunkAsync(volumeName, entry.FileId, i);
            byte[] plain = E2eeCrypto.DecryptChunk(enc, fileKey, i, fileSalt, revision);
            await output.WriteAsync(plain, ct);
            progress?.Report((double)(i + 1) / entry.ChunkCount * 100);
        }
    }

    /// <summary>復号済みバイト列でファイルを開く (画像 / テキスト表示用)。</summary>
    public async Task<MemoryStream> OpenDecryptedAsync(string volumeName, E2eeFileEntry entry,
        IProgress<double>? progress = null, CancellationToken ct = default)
    {
        long plainLen = ComputePlainLength(entry);
        if (plainLen > MaxInMemoryDownloadBytes)
            throw new InvalidOperationException("ファイルが大きすぎてメモリに展開できません。");
        var ms = new MemoryStream((int)plainLen);
        await DownloadAsync(volumeName, entry, ms, progress, ct);
        ms.Position = 0;
        return ms;
    }

    /// <summary>平文ストリームを E2EE 暗号化してアップロードする。</summary>
    /// <returns>作成されたファイルのエントリ情報 (fileId / chunkCount)。</returns>
    public async Task<(string FileId, int ChunkCount)> UploadAsync(string volumeName, string fileName,
        Stream input, long plainLength, IProgress<double>? progress = null, CancellationToken ct = default)
    {
        byte[] masterKey = e2eeSession.GetMasterKey(volumeName);
        int chunkSize = e2eeSession.GetChunkSize(volumeName);

        int chunkCount = Math.Max(1, (int)((plainLength + chunkSize - 1) / chunkSize));
        long encryptedLength = plainLength + E2eeCrypto.SaltSize + (long)E2eeCrypto.GcmTagSize * chunkCount;
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        string encryptedName = E2eeCrypto.EncryptFilename(fileName, masterKey);

        (string fileId, string lease) = await api.CreateFileAsync(volumeName, encryptedName, encryptedLength, chunkCount);
        try
        {
            var buffer = new byte[chunkSize];
            for (int i = 0; i < chunkCount; i++)
            {
                ct.ThrowIfCancellationRequested();
                int read = await ReadBlockAsync(input, buffer, ct);
                // isFirstChunk: true で chunk 0 の先頭に fileSalt が平文埋め込みされる
                byte[] enc = E2eeCrypto.EncryptChunk(buffer[..read], fileKey, i, fileSalt, isFirstChunk: i == 0);
                await api.UploadChunkAsync(volumeName, fileId, i, enc, lease);
                progress?.Report((double)(i + 1) / chunkCount * 100);
            }
            await api.FinalizeFileAsync(volumeName, fileId, encryptedLength, lease, chunkCount);
            return (fileId, chunkCount);
        }
        catch
        {
            await CleanupFailedUploadAsync(api, volumeName, fileId, lease);
            throw;
        }
        finally
        {
            try { await api.ReleaseWriteLeaseAsync(volumeName, fileId, lease); } catch { /* ベストエフォート */ }
        }
    }

    /// <summary>暗号化長から平文長を計算する (chunk 0 の salt 分 + チャンクごとの GCM tag 分を除く)。</summary>
    public static long ComputePlainLength(E2eeFileEntry entry) =>
        entry.EncryptedLength - E2eeCrypto.SaltSize - (long)E2eeCrypto.GcmTagSize * entry.ChunkCount;

    /// <summary>表示名を復号する。復号できない (他ユーザーの鍵で暗号化された等) 場合は null。</summary>
    public static string? TryDecryptName(string encryptedName, byte[] masterKey)
    {
        try
        {
            return E2eeCrypto.DecryptFilename(encryptedName, masterKey);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }

    private static async Task CleanupFailedUploadAsync(CistaNasApiClient api, string volumeName, string fileId, string lease)
    {
        try { await api.DeleteFileAsync(volumeName, fileId, lease); }
        catch { /* ロールバック失敗は無視 (finalize 未了の孤立ファイルは finalize 前提のため自然消滅) */ }
    }

    private static async Task<int> ReadBlockAsync(Stream input, byte[] buffer, CancellationToken ct)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = await input.ReadAsync(buffer.AsMemory(total), ct);
            if (read == 0) break;
            total += read;
        }
        return total;
    }
}
