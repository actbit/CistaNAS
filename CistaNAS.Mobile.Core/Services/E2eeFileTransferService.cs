using System.Security.Cryptography;
using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Mobile.Core.Services;

/// <summary>
/// E2EE ボリュームのファイル転送 (チャンク暗号化 / 復号 + write-lease 制御)。
/// 暗号化プロトコルは Shared.E2eeCrypto (WASM e2ee.js と相互運用) に一本化。
/// crypto format v2 (entry.KeyEpoch ≥ 1) は共有 GroupKey + per-file DEK パスに分岐する。
/// </summary>
public sealed class E2eeFileTransferService(CistaNasApiClient api, E2eeSession e2eeSession)
{
    /// <summary>メモリ上での復号サイズ上限。超えるファイルはキャッシュファイル経由にフォールバック。</summary>
    public const long MaxInMemoryDownloadBytes = 50 * 1024 * 1024;

    /// <summary>
    /// E2EE ファイルを復号しながら <paramref name="output"/> へダウンロードする。
    /// v1: チャンク 0 の先頭 16B (fileSalt) から masterKey 派生の fileKey を導出する。
    /// v2: WrappedFileKey を GroupKey でアンラップした per-file DEK で復号する。
    /// </summary>
    public async Task DownloadAsync(string volumeName, E2eeFileEntry entry, Stream output,
        IProgress<double>? progress = null, CancellationToken ct = default)
    {
        int chunkSize = e2eeSession.GetChunkSize(volumeName);

        if (entry.KeyEpoch >= 1)
        {
            await DownloadV2Async(volumeName, entry, output, progress, ct);
            return;
        }

        byte[] masterKey = e2eeSession.GetMasterKey(volumeName);

        // チャンク 0 から fileSalt を取得して fileKey を導出
        (byte[] data0, int revision0, _) = await api.DownloadChunkAsync(volumeName, entry.FileId, 0);
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
            (byte[] enc, int revision, _) = await api.DownloadChunkAsync(volumeName, entry.FileId, i);
            byte[] plain = E2eeCrypto.DecryptChunk(enc, fileKey, i, fileSalt, revision);
            await output.WriteAsync(plain, ct);
            progress?.Report((double)(i + 1) / entry.ChunkCount * 100);
        }
    }

    /// <summary>crypto format v2 のダウンロード。チャンク復号にはチャンク固有 keyEpoch（アップロード時に刻印）を使う。</summary>
    private async Task DownloadV2Async(string volumeName, E2eeFileEntry entry, Stream output,
        IProgress<double>? progress, CancellationToken ct)
    {
        var v2 = e2eeSession.GetV2State(volumeName);
        string volumeId = v2.VolumeIdString;
        byte[] groupKey = v2.GetGroupKey(entry.KeyEpoch);

        if (entry.WrappedFileKey is null)
            throw new InvalidOperationException("v2 ファイルの WrappedFileKey がカタログにありません。");
        byte[] fileKey = E2eeV2.UnwrapFileKey(entry.WrappedFileKey.Nonce, entry.WrappedFileKey.Ciphertext,
            entry.WrappedFileKey.Tag, groupKey, volumeId, entry.FileId, entry.KeyEpoch);
        try
        {
            // チャンク 0 の先頭 16B (fileSalt) を取得
            (byte[] data0, int revision0, int epoch0) = await api.DownloadChunkAsync(volumeName, entry.FileId, 0);
            if (data0.Length < E2eeCrypto.SaltSize + E2eeCrypto.GcmTagSize)
                throw new InvalidOperationException("チャンク 0 が不正です。");
            byte[] fileSalt = new byte[E2eeCrypto.SaltSize];
            Buffer.BlockCopy(data0, 0, fileSalt, 0, E2eeCrypto.SaltSize);

            var ctx0 = new E2eeChunkContext(volumeId, entry.FileId, 0, revision0,
                epoch0 > 0 ? epoch0 : entry.KeyEpoch);
            byte[] plain0 = E2eeV2.DecryptChunk(data0, fileKey, ctx0, fileSalt);
            await output.WriteAsync(plain0, ct);

            for (int i = 1; i < entry.ChunkCount; i++)
            {
                ct.ThrowIfCancellationRequested();
                (byte[] enc, int revision, int chunkEpoch) = await api.DownloadChunkAsync(volumeName, entry.FileId, i);
                var ctx = new E2eeChunkContext(volumeId, entry.FileId, i, revision,
                    chunkEpoch > 0 ? chunkEpoch : entry.KeyEpoch);
                byte[] plain = E2eeV2.DecryptChunk(enc, fileKey, ctx, fileSalt);
                await output.WriteAsync(plain, ct);
                progress?.Report((double)(i + 1) / entry.ChunkCount * 100);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
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

    /// <summary>
    /// 平文ストリームを E2EE 暗号化してアップロードする。
    /// セッションに共有 v2 状態があれば v2 (per-file DEK + GroupKey wrap) で、なければ v1 で暗号化する。
    /// </summary>
    /// <returns>作成されたファイルのエントリ情報 (fileId / chunkCount)。</returns>
    public async Task<(string FileId, int ChunkCount)> UploadAsync(string volumeName, string fileName,
        Stream input, long plainLength, IProgress<double>? progress = null, CancellationToken ct = default)
    {
        if (e2eeSession.TryGetV2State(volumeName, out var v2))
        {
            return await UploadV2Async(volumeName, v2!, fileName, input, plainLength, progress, ct);
        }

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

    /// <summary>crypto format v2 のアップロード。per-file DEK を生成して現行 epoch の GroupKey でラップする。</summary>
    private async Task<(string FileId, int ChunkCount)> UploadV2Async(string volumeName, E2eeV2VolumeState v2,
        string fileName, Stream input, long plainLength, IProgress<double>? progress, CancellationToken ct)
    {
        string volumeId = v2.VolumeIdString;
        int keyEpoch = v2.CurrentEpoch;
        if (keyEpoch < 1)
            throw new InvalidOperationException("共有 v2 の GroupKey がありません（共有から削除された可能性があります）。");
        byte[] groupKey = v2.GetGroupKey(keyEpoch);
        int chunkSize = e2eeSession.GetChunkSize(volumeName);

        int chunkCount = Math.Max(1, (int)((plainLength + chunkSize - 1) / chunkSize));
        long encryptedLength = plainLength + E2eeCrypto.SaltSize + (long)E2eeCrypto.GcmTagSize * chunkCount;
        byte[] fileSalt = E2eeV2.GenerateFileSalt();
        byte[] fileKey = E2eeV2.GenerateFileKey();
        // v2 のファイル名は GroupKey で暗号化する（v1 = masterKey）
        string encryptedName = E2eeCrypto.EncryptFilename(fileName, groupKey);

        // fileId をクライアント側で先に決定する（WrappedFileKey の AAD に fileId が bind されるため）。
        string fileId = Guid.NewGuid().ToString("N");
        var (nonce, ctBytes, tag) = E2eeV2.WrapFileKey(fileKey, groupKey, volumeId, fileId, keyEpoch);
        try
        {
            (fileId, string lease) = await api.CreateFileAsync(volumeName, encryptedName, encryptedLength, chunkCount,
                keyEpoch, new WrappedAeadKey
                {
                    Algorithm = "aes-256-gcm",
                    Nonce = nonce,
                    Ciphertext = ctBytes,
                    Tag = tag,
                }, fileId);
            try
            {
                var buffer = new byte[chunkSize];
                for (int i = 0; i < chunkCount; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    int read = await ReadBlockAsync(input, buffer, ct);
                    var chunkCtx = new E2eeChunkContext(volumeId, fileId, i, Revision: 0, keyEpoch);
                    byte[] enc = E2eeV2.EncryptChunk(buffer[..read], fileKey, chunkCtx, isFirstChunk: i == 0, fileSalt);
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
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>暗号化長から平文長を計算する (chunk 0 の salt 分 + チャンクごとの GCM tag 分を除く)。</summary>
    public static long ComputePlainLength(E2eeFileEntry entry) =>
        entry.EncryptedLength - E2eeCrypto.SaltSize - (long)E2eeCrypto.GcmTagSize * entry.ChunkCount;

    /// <summary>
    /// 表示名を復号する。鍵は v1 では masterKey、v2 では GroupKey を渡す。
    /// 復号できない (他ユーザーの鍵で暗号化された等) 場合は null。
    /// </summary>
    public static string? TryDecryptName(string encryptedName, byte[] key)
    {
        try
        {
            return E2eeCrypto.DecryptFilename(encryptedName, key);
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
