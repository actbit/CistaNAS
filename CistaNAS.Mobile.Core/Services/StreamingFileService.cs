using System.Security.Cryptography;
using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Mobile.Core.Services;

/// <summary>サーバーの必要な範囲／暗号化チャンクだけを取得する。ディスクへの保存は行わない。</summary>
public sealed class StreamingFileService(CistaNasApiClient api, E2eeSession session)
{
    public ReadOnlyFileContent OpenServerFile(string volume, string path, FileMetadata metadata, CancellationToken ct)
        => new ServerContent(api, volume, path, metadata.Length, ct);

    public async Task<ReadOnlyFileContent> OpenE2eeFileAsync(string volume, string name, E2eeFileEntry entry,
        CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        int chunkSize = session.GetChunkSize(volume);
        long length = E2eeFileTransferService.ComputePlainLength(entry);
        if (length < 0 || entry.ChunkCount != E2eeCrypto.ComputeChunkCount(length, chunkSize))
            throw new InvalidDataException("暗号化ファイルのサイズ情報が不正です。");
        byte[]? key = null;
        byte[]? firstPlain = null;
        try
        {
            // v2の鍵状態はAPI待機前にスナップショットし、セッション終了のゼロ消去と競合させない。
            string? volumeId = null;
            byte[]? master = null;
            if (entry.KeyEpoch > 0)
            {
                var state = session.GetV2State(volume);
                volumeId = state.VolumeIdString;
                var wrapped = entry.WrappedFileKey ?? throw new InvalidDataException("ファイルの復号鍵がありません。");
                key = E2eeV2.UnwrapFileKey(wrapped.Nonce, wrapped.Ciphertext, wrapped.Tag,
                    state.GetGroupKey(entry.KeyEpoch), volumeId, entry.FileId, entry.KeyEpoch);
            }
            else master = (byte[])session.GetMasterKey(volume).Clone();
            byte[] first;
            int revision;
            int epoch;
            try
            {
                (first, revision, epoch) = await api.DownloadChunkAsync(volume, entry.FileId, 0, ct,
                    checked(chunkSize + E2eeCrypto.SaltSize + E2eeCrypto.GcmTagSize)).ConfigureAwait(false);
                if (first.Length < E2eeCrypto.SaltSize + E2eeCrypto.GcmTagSize)
                    throw new InvalidDataException("先頭チャンクが不正です。");
                if (master is not null) key = E2eeCrypto.DeriveFileKey(master, first[..E2eeCrypto.SaltSize]);
            }
            finally { if (master is not null) CryptographicOperations.ZeroMemory(master); }
            byte[] salt = first[..E2eeCrypto.SaltSize];
            firstPlain = volumeId is null
                ? E2eeCrypto.DecryptChunk(first, key!, 0, salt, revision)
                : E2eeV2.DecryptChunk(first, key!, new E2eeChunkContext(volumeId, entry.FileId, 0,
                    revision, epoch > 0 ? epoch : entry.KeyEpoch), salt);
            if (firstPlain.Length != Math.Min(length, chunkSize))
                throw new InvalidDataException("先頭チャンクの長さが不正です。");
            ct.ThrowIfCancellationRequested();
            var content = new E2eeContent(api, volume, name, length, entry.FileId, chunkSize,
                entry.KeyEpoch, volumeId, key!, salt, firstPlain, ct);
            key = null;
            firstPlain = null; // contentが所有し、閉じる時に消去する。
            return content;
        }
        finally
        {
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (firstPlain is not null) CryptographicOperations.ZeroMemory(firstPlain);
        }
    }

    private sealed class ServerContent(CistaNasApiClient api, string volume, string path, long length, CancellationToken ct)
        : ReadOnlyFileContent(Path.GetFileName(path), length, ct)
    {
        protected override async ValueTask<int> ReadCoreAsync(long offset, Memory<byte> destination, CancellationToken ct)
        {
            byte[] bytes = await api.DownloadFileRangeAsync(volume, path, offset, destination.Length, ct, requireExactRange: true).ConfigureAwait(false);
            try
            {
                if (bytes.Length != destination.Length) throw new EndOfStreamException("読み取り範囲の長さが一致しません。");
                bytes.CopyTo(destination);
                return bytes.Length;
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }

    private sealed class E2eeContent(CistaNasApiClient api, string volume, string name, long length, string fileId,
        int chunkSize, int keyEpoch, string? volumeId, byte[] key, byte[] salt, byte[] first, CancellationToken ct)
        : ReadOnlyFileContent(name, length, ct)
    {
        private int _index;
        private byte[] _plain = first;

        protected override async ValueTask<int> ReadCoreAsync(long offset, Memory<byte> destination, CancellationToken ct)
        {
            int copied = 0;
            while (copied < destination.Length)
            {
                long position = offset + copied;
                int index = checked((int)(position / chunkSize));
                if (index != _index)
                {
                    CryptographicOperations.ZeroMemory(_plain);
                    _plain = [];
                    _index = -1;
                    var (bytes, revision, epoch) = await api.DownloadChunkAsync(volume, fileId, index, ct,
                        checked(chunkSize + E2eeCrypto.SaltSize + E2eeCrypto.GcmTagSize)).ConfigureAwait(false);
                    if (index == 0 && !bytes.AsSpan(0, Math.Min(bytes.Length, E2eeCrypto.SaltSize)).SequenceEqual(salt))
                        throw new InvalidDataException("表示中にファイルが置き換えられました。");
                    byte[] plain = volumeId is null
                        ? E2eeCrypto.DecryptChunk(bytes, key, index, salt, revision)
                        : E2eeV2.DecryptChunk(bytes, key, new E2eeChunkContext(volumeId, fileId, index,
                            revision, epoch > 0 ? epoch : keyEpoch), salt);
                    if (plain.Length != Math.Min(chunkSize, Length - (long)index * chunkSize))
                    {
                        CryptographicOperations.ZeroMemory(plain);
                        throw new InvalidDataException("チャンクの長さが不正です。");
                    }
                    _plain = plain;
                    _index = index;
                }
                int start = (int)(position % chunkSize);
                int count = Math.Min(_plain.Length - start, destination.Length - copied);
                _plain.AsMemory(start, count).CopyTo(destination[copied..]);
                copied += count;
            }
            return copied;
        }

        protected override void ClearBuffers()
        {
            CryptographicOperations.ZeroMemory(_plain);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(salt);
            _plain = [];
        }
    }
}
