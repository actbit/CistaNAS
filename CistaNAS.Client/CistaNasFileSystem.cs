using System.Collections.Concurrent;
using System.Security.AccessControl;
using CistaNAS.Client.Api;
using CistaNAS.Client.Crypto;
using DokanNet;

namespace CistaNAS.Client;

/// <summary>
/// Dokan ベースの仮想ファイルシステム。
/// CistaNAS のボリューム（E2EE/非E2EE両対応）を Windows エクスプローラーにマウントする。
/// </summary>
public sealed class CistaNasFileSystem : IDokanOperations
{
    private readonly CistaNasApiClient _api;
    private readonly byte[]? _masterKey;  // E2EE モードでのみ使用
    private readonly string _volumeName;
    private readonly int _chunkSize;
    private readonly bool _isE2ee;  // E2EE モードフラグ

    // Level 1: plainName → fileId（E2EEのみ）
    private readonly ConcurrentDictionary<string, string> _fileIdCache = new(StringComparer.OrdinalIgnoreCase);

    // Level 2: fileId → FileCache（E2EEのみ、メタデータ + LRU チャンクキャッシュ）
    private readonly ConcurrentDictionary<string, FileCache> _cache = new(StringComparer.Ordinal);

    // Level 3: ファイル一覧キャッシュ（TTL ベース）
    private readonly ListingCache _listingCache = new();

    // クオータ統計キャッシュ（Write/Delete 後に無効化）
    private (long UserUsedBytes, long UserQuotaBytes)? _cachedStats;
    private readonly object _statsLock = new();

    /// <summary>E2EE モードでファイルシステムを作成。</summary>
    public CistaNasFileSystem(CistaNasApiClient api, byte[] masterKey, string volumeName, int chunkSize = 1048576)
    {
        _api = api;
        _masterKey = masterKey;
        _volumeName = volumeName;
        _chunkSize = chunkSize;
        _isE2ee = true;
    }

    /// <summary>非E2EE モードでファイルシステムを作成。</summary>
    public CistaNasFileSystem(CistaNasApiClient api, string volumeName)
    {
        _api = api;
        _masterKey = null;
        _volumeName = volumeName;
        _chunkSize = 0;
        _isE2ee = false;
    }

    // ---- 内部クラス: ファイルキャッシュ（LRU チャンク驱逐付き） ----

    internal sealed class FileCache
    {
        public string PlainName = "";
        public string FileId = "";
        public int ChunkCount;
        public long EncryptedLength;
        public long PlainLength;
        public byte[]? FileKey;

        private readonly Dictionary<int, byte[]> _chunks = new();
        private readonly LinkedList<int> _lru = new();
        private readonly object _chunkLock = new();
        private const int MaxChunks = 16; // 1MB × 16 = 16MB/file 上限

        public bool TryGetChunk(int index, out byte[]? chunk)
        {
            lock (_chunkLock)
            {
                if (_chunks.TryGetValue(index, out chunk))
                {
                    _lru.Remove(index);
                    _lru.AddFirst(index);
                    return true;
                }
                return false;
            }
        }

        public void PutChunk(int index, byte[] data)
        {
            lock (_chunkLock)
            {
                if (_chunks.ContainsKey(index))
                {
                    _lru.Remove(index);
                    _lru.AddFirst(index);
                    return;
                }

                _chunks[index] = data;
                _lru.AddFirst(index);

                while (_chunks.Count > MaxChunks)
                {
                    int evict = _lru.Last!.Value;
                    _lru.RemoveLast();
                    _chunks.Remove(evict);
                }
            }
        }

        public void ClearChunks()
        {
            lock (_chunkLock)
            {
                _chunks.Clear();
                _lru.Clear();
            }
        }
    }

    // ---- 内部クラス: ファイル一覧 TTL キャッシュ ----

    internal sealed class ListingCache
    {
        private List<(string FileId, string PlainName, FileInformation Info)>? _entries;
        private DateTime _expiresAt;
        private readonly TimeSpan _ttl = TimeSpan.FromSeconds(5);
        private readonly object _lock = new();

        public bool TryGet(out List<(string FileId, string PlainName, FileInformation Info)> entries)
        {
            lock (_lock)
            {
                if (_entries is not null && DateTime.UtcNow < _expiresAt)
                {
                    entries = _entries;
                    return true;
                }
                entries = null!;
                return false;
            }
        }

        public void Set(List<(string FileId, string PlainName, FileInformation Info)> entries)
        {
            lock (_lock)
            {
                _entries = entries;
                _expiresAt = DateTime.UtcNow + _ttl;
            }
        }

        public void Invalidate()
        {
            lock (_lock)
            {
                _entries = null;
            }
        }
    }

    // ---- 内部クラス: 書き込みバッファ ----

    internal sealed class WriteState
    {
        public string PlainName;
        public string? ExistingFileId; // 上書き時の旧ファイルID
        private byte[] _buffer;
        private long _writtenLength;    // 実際に書き込んだ最大位置
        private long _declaredSize = -1; // SetEndOfFile で指定されたサイズ
        private readonly object _lock = new();

        public WriteState(string plainName, string? existingFileId, int initialCapacity = 64 * 1024)
        {
            PlainName = plainName;
            ExistingFileId = existingFileId;
            _buffer = new byte[initialCapacity];
            _writtenLength = 0;
        }

        public long CurrentSize
        {
            get
            {
                lock (_lock) { return _declaredSize >= 0 ? _declaredSize : _writtenLength; }
            }
        }

        public void Write(byte[] data, int dataOffset, int count, long fileOffset)
        {
            lock (_lock)
            {
                long endOffset = fileOffset + count;
                EnsureCapacity(endOffset);
                Buffer.BlockCopy(data, dataOffset, _buffer, (int)fileOffset, count);
                if (endOffset > _writtenLength)
                    _writtenLength = endOffset;
            }
        }

        public void SetDeclaredSize(long size)
        {
            lock (_lock)
            {
                _declaredSize = size;
                if (size > _buffer.Length)
                    EnsureCapacity(size);
            }
        }

        public byte[] GetFinalData()
        {
            lock (_lock)
            {
                int length = _declaredSize >= 0
                    ? (int)Math.Min(_declaredSize, _writtenLength > 0 ? _writtenLength : _declaredSize)
                    : (int)_writtenLength;
                if (length <= 0) return [];
                byte[] result = new byte[length];
                Array.Copy(_buffer, result, length);
                return result;
            }
        }

        private void EnsureCapacity(long needed)
        {
            if (needed <= _buffer.Length) return;
            long newCapacity = Math.Max(_buffer.Length * 2L, needed);
            if (newCapacity > int.MaxValue) newCapacity = int.MaxValue;
            byte[] newBuffer = new byte[(int)newCapacity];
            Array.Copy(_buffer, newBuffer, Math.Min(_buffer.Length, (int)newCapacity));
            _buffer = newBuffer;
        }
    }

    // ====================================================================
    // IDokanOperations 実装
    // ====================================================================

    public void Cleanup(string fileName, IDokanFileInfo info)
    {
        if (info.Context is WriteState ws)
        {
            try
            {
                UploadWriteState(ws);
            }
            catch { /* Cleanup は void なのでエラーを飲む */ }
            finally
            {
                info.Context = null;
            }
        }
    }

    public void CloseFile(string fileName, IDokanFileInfo info)
    {
        if (info.Context is WriteState)
            info.Context = null;
    }

    public NtStatus CreateFile(string fileName, DokanNet.FileAccess access, FileShare share,
        FileMode mode, FileOptions options, FileAttributes attributes, IDokanFileInfo info)
    {
        string plainName = fileName.TrimStart('\\');

        if (mode == FileMode.Open || mode == FileMode.OpenOrCreate)
        {
            if (fileName == "\\")
            {
                info.IsDirectory = true;
                return DokanResult.Success;
            }

            // 非E2EE モード: ファイルパスを設定
            if (!_isE2ee)
            {
                info.Context = plainName;
                return DokanResult.Success;
            }

            // E2EE モード: fileId で管理
            var fileId = FindFileId(plainName);
            if (fileId is not null)
            {
                // 書き込みアクセスがある場合は上書きモード
                if ((access & DokanNet.FileAccess.WriteData) != 0)
                {
                    info.Context = new WriteState(plainName, existingFileId: fileId);
                    return DokanResult.Success;
                }
                info.Context = fileId;
                return DokanResult.Success;
            }

            if (mode == FileMode.OpenOrCreate)
            {
                info.Context = new WriteState(plainName, existingFileId: null);
                return DokanResult.Success;
            }

            return DokanResult.FileNotFound;
        }

        if (mode == FileMode.CreateNew)
        {
            // 非E2EE モード: 新規作成
            if (!_isE2ee)
            {
                info.Context = new WriteState(plainName, existingFileId: null);
                return DokanResult.Success;
            }

            // E2EE モード
            var existing = FindFileId(plainName);
            if (existing is not null)
                return DokanResult.FileExists;

            info.Context = new WriteState(plainName, existingFileId: null);
            return DokanResult.Success;
        }

        if (mode == FileMode.Create)
        {
            // Create: 既存ファイルを上書き

            // 非E2EE モード
            if (!_isE2ee)
            {
                info.Context = new WriteState(plainName, existingFileId: plainName);
                return DokanResult.Success;
            }

            // E2EE モード: 旧IDを保持して Cleanup で削除
            var existing = FindFileId(plainName);
            info.Context = new WriteState(plainName, existingFileId: existing);
            return DokanResult.Success;
        }

        return DokanResult.Success;
    }

    public NtStatus ReadFile(string fileName, byte[] buffer, out int bytesRead, long offset, IDokanFileInfo info)
    {
        bytesRead = 0;

        // 非E2EE モード: 通常ファイルダウンロード
        if (!_isE2ee)
        {
            if (info.Context is not string filePath)
                return DokanResult.InvalidParameter;

            try
            {
                var data = CistaNasApiClientFiles.DownloadFileAsync(_api, _volumeName, filePath).GetAwaiter().GetResult();
                if (offset >= data.Length)
                    return DokanResult.Success;

                int copyCount = Math.Min(buffer.Length, (int)(data.Length - offset));
                Array.Copy(data, offset, buffer, 0, copyCount);
                bytesRead = copyCount;
                return DokanResult.Success;
            }
            catch
            {
                return DokanResult.InternalError;
            }
        }

        // E2EE モード: チャンクダウンロード + 復号化
        if (info.Context is not string fileId)
            return DokanResult.InvalidParameter;

        var cache = GetOrCreateCache(fileId);
        if (cache is null) return DokanResult.FileNotFound;

        // チャンク 0 から salt を抽出して fileKey を確定
        if (cache.FileKey is null)
        {
            try
            {
                var encData = _api.DownloadChunkAsync(_volumeName, fileId, 0).GetAwaiter().GetResult();
                if (encData.Length <= 16)
                    return DokanResult.InternalError;

                byte[] salt = new byte[16];
                Buffer.BlockCopy(encData, 0, salt, 0, 16);
                cache.FileKey = E2eeCrypto.DeriveFileKey(_masterKey!, salt);

                // チャンク 0 もキャッシュしておく（次回の ReadFile で再利用）
                var chunk = E2eeCrypto.DecryptChunk(encData, cache.FileKey, 0, out _);
                cache.PutChunk(0, chunk);
            }
            catch
            {
                return DokanResult.InternalError;
            }
        }

        byte[] fileKey = cache.FileKey;

        // シーク最適化: offset から開始チャンクを計算
        int startChunk = cache.ChunkCount > 0
            ? Math.Min((int)(offset / _chunkSize), cache.ChunkCount - 1)
            : 0;
        long fileOffset = (long)startChunk * _chunkSize;

        for (int i = startChunk; i < cache.ChunkCount && bytesRead < buffer.Length; i++)
        {
            if (offset + bytesRead >= cache.PlainLength)
                break;

            if (!cache.TryGetChunk(i, out var chunk))
            {
                try
                {
                    var encData = _api.DownloadChunkAsync(_volumeName, fileId, i).GetAwaiter().GetResult();
                    chunk = E2eeCrypto.DecryptChunk(encData, fileKey, i, out _);
                    cache.PutChunk(i, chunk);
                }
                catch
                {
                    return DokanResult.InternalError;
                }
            }

            long chunkStart = fileOffset;
            long chunkEnd = chunkStart + chunk!.Length;

            if (offset < chunkEnd)
            {
                int copyOffset = (int)Math.Max(0, offset - chunkStart);
                int maxCopy = Math.Min(chunk.Length - copyOffset, buffer.Length - bytesRead);
                if (offset + bytesRead + maxCopy > cache.PlainLength)
                    maxCopy = (int)Math.Max(0, cache.PlainLength - offset - bytesRead);
                if (maxCopy > 0)
                {
                    Buffer.BlockCopy(chunk, copyOffset, buffer, bytesRead, maxCopy);
                    bytesRead += maxCopy;
                }
            }

            fileOffset += chunk.Length;
        }

        return DokanResult.Success;
    }

    public NtStatus WriteFile(string fileName, byte[] buffer, out int bytesWritten, long offset, IDokanFileInfo info)
    {
        bytesWritten = 0;

        if (info.Context is WriteState ws)
        {
            ws.Write(buffer, 0, buffer.Length, offset);
            bytesWritten = buffer.Length;
            return DokanResult.Success;
        }

        // 読み取り専用ハンドルへの書き込み
        return DokanResult.AccessDenied;
    }

    public NtStatus FlushFileBuffers(string fileName, IDokanFileInfo info) => DokanResult.Success;

    public NtStatus GetFileInformation(string fileName, out FileInformation fileInfo, IDokanFileInfo info)
    {
        fileInfo = new FileInformation
        {
            FileName = fileName.TrimStart('\\'),
            Attributes = fileName == "\\" ? FileAttributes.Directory : FileAttributes.Normal,
            Length = 0,
        };

        if (fileName == "\\") return DokanResult.Success;

        // 書き込み中のファイル
        if (info.Context is WriteState ws)
        {
            fileInfo.FileName = ws.PlainName;
            fileInfo.Length = ws.CurrentSize;
            return DokanResult.Success;
        }

        // 非E2EE モード: ファイルパスから取得
        if (!_isE2ee)
        {
            var filePath = info.Context as string ?? fileName.TrimStart('\\');
            try
            {
                var entries = CistaNasApiClientFiles.ListFilesAsync(_api, _volumeName).GetAwaiter().GetResult();
                var entry = entries.FirstOrDefault(e => string.Equals(e.Name, filePath, StringComparison.OrdinalIgnoreCase));
                if (entry is null) return DokanResult.FileNotFound;

                fileInfo.Length = entry.Length;
                fileInfo.FileName = entry.Name;
                fileInfo.CreationTime = entry.CreatedAt.DateTime;
                fileInfo.LastWriteTime = entry.ModifiedAt.DateTime;
            }
            catch { return DokanResult.InternalError; }
            return DokanResult.Success;
        }

        // E2EE モード: fileId から取得
        var fileId = info.Context as string ?? FindFileId(fileName.TrimStart('\\'));
        if (fileId is null) return DokanResult.FileNotFound;

        var cache = GetOrCreateCache(fileId);
        if (cache is not null)
        {
            fileInfo.Length = cache.PlainLength;
            fileInfo.FileName = cache.PlainName;
        }

        return DokanResult.Success;
    }

    public NtStatus FindFiles(string fileName, out IList<FileInformation> files, IDokanFileInfo info)
    {
        files = new List<FileInformation>();

        // キャッシュヒットチェック
        if (_listingCache.TryGet(out var cached))
        {
            foreach (var (_, _, fi) in cached)
                files.Add(fi);
            return DokanResult.Success;
        }

        try
        {
            // 非E2EE モード: 通常ファイル API を使用
            if (!_isE2ee)
            {
                var entries = CistaNasApiClientFiles.ListFilesAsync(_api, _volumeName).GetAwaiter().GetResult();
                var listingEntries = new List<(string FileId, string PlainName, FileInformation Info)>();

                foreach (var entry in entries)
                {
                    var fi = new FileInformation
                    {
                        FileName = entry.Name,
                        Attributes = FileAttributes.Normal,
                        Length = entry.Length,
                        CreationTime = entry.CreatedAt.DateTime,
                        LastWriteTime = entry.ModifiedAt.DateTime,
                    };

                    listingEntries.Add((entry.Name, entry.Name, fi));
                    files.Add(fi);
                }

                _listingCache.Set(listingEntries);
                return DokanResult.Success;
            }

            // E2EE モード: ファイル名復号化
            var e2eeEntries = _api.ListFilesAsync(_volumeName).GetAwaiter().GetResult();
            var e2eeListingEntries = new List<(string FileId, string PlainName, FileInformation Info)>();

            foreach (var entry in e2eeEntries)
            {
                string plainName;
                try { plainName = E2eeCrypto.DecryptFilename(entry.EncryptedName, _masterKey!); }
                catch { plainName = $"<{entry.FileId[..8]}...>"; }

                long plainLength = Math.Max(0, entry.EncryptedLength - 16L - (long)entry.ChunkCount * 16);

                var fi = new FileInformation
                {
                    FileName = plainName,
                    Attributes = FileAttributes.Normal,
                    Length = plainLength,
                    CreationTime = entry.CreatedAt.DateTime,
                    LastWriteTime = entry.ModifiedAt.DateTime,
                };

                e2eeListingEntries.Add((entry.FileId, plainName, fi));
                files.Add(fi);

                // 名前キャッシュとファイルキャッシュも更新
                _fileIdCache.TryAdd(plainName, entry.FileId);
                if (!_cache.ContainsKey(entry.FileId))
                {
                    _cache.TryAdd(entry.FileId, new FileCache
                    {
                        PlainName = plainName,
                        FileId = entry.FileId,
                        ChunkCount = entry.ChunkCount,
                        EncryptedLength = entry.EncryptedLength,
                        PlainLength = plainLength,
                    });
                }
            }

            _listingCache.Set(e2eeListingEntries);
            return DokanResult.Success;
        }
        catch
        {
            return DokanResult.InternalError;
        }
    }

    public NtStatus FindFilesWithPattern(string fileName, string searchPattern,
        out IList<FileInformation> files, IDokanFileInfo info)
    {
        var status = FindFiles(fileName, out files, info);
        if (status != DokanResult.Success) return status;

        if (searchPattern != "*")
        {
            files = files.Where(f => IsMatch(f.FileName, searchPattern)).ToList();
        }
        return DokanResult.Success;
    }

    public NtStatus DeleteFile(string fileName, IDokanFileInfo info)
    {
        string plainName = fileName.TrimStart('\\');

        // 非E2EE モード: ファイルパスで削除
        if (!_isE2ee)
        {
            try { CistaNasApiClientFiles.DeleteFileAsync(_api, _volumeName, plainName).GetAwaiter().GetResult(); }
            catch (Exception) { return DokanResult.InternalError; }

            _listingCache.Invalidate();
            lock (_statsLock) { _cachedStats = null; }
            return DokanResult.Success;
        }

        // E2EE モード: fileId で削除
        var fileId = FindFileId(plainName);
        if (fileId is null) return DokanResult.FileNotFound;

        try { _api.DeleteFileAsync(_volumeName, fileId).GetAwaiter().GetResult(); }
        catch (Exception) { return DokanResult.InternalError; }

        // 全レベルのキャッシュを無効化
        _cache.TryRemove(fileId, out _);
        _fileIdCache.TryRemove(plainName, out _);
        _listingCache.Invalidate();
        lock (_statsLock) { _cachedStats = null; }

        return DokanResult.Success;
    }

    public NtStatus DeleteDirectory(string fileName, IDokanFileInfo info) => DokanResult.Success;

    public NtStatus MoveFile(string oldName, string newName, bool replace, IDokanFileInfo info)
        => DokanResult.NotImplemented;

    public NtStatus SetEndOfFile(string fileName, long length, IDokanFileInfo info)
    {
        if (info.Context is WriteState ws)
        {
            ws.SetDeclaredSize(length);
            return DokanResult.Success;
        }
        return DokanResult.Success;
    }

    public NtStatus SetAllocationSize(string fileName, long length, IDokanFileInfo info)
        => DokanResult.Success;

    public NtStatus GetDiskFreeSpace(out long freeBytesAvailable, out long totalNumberOfBytes,
        out long totalNumberOfFreeBytes, IDokanFileInfo info)
    {
        var stats = GetOrRefreshStats();
        const long unlimited = 100L * 1024 * 1024 * 1024 * 1024; // 100 TB fallback
        long quota = stats.UserQuotaBytes > 0 ? stats.UserQuotaBytes : unlimited;
        long free = Math.Max(0, quota - stats.UserUsedBytes);
        freeBytesAvailable = free;
        totalNumberOfBytes = quota;
        totalNumberOfFreeBytes = free;
        return DokanResult.Success;
    }

    public NtStatus GetVolumeInformation(out string volumeName, out FileSystemFeatures features,
        out string fileSystemName, out uint maximumComponentLength, IDokanFileInfo info)
    {
        volumeName = _isE2ee ? "CistaNAS E2EE" : "CistaNAS";
        features = FileSystemFeatures.CasePreservedNames | FileSystemFeatures.SupportsRemoteStorage;
        fileSystemName = "CistaNAS";
        maximumComponentLength = 255;
        return DokanResult.Success;
    }

    public NtStatus GetFileSecurity(string fileName, out FileSystemSecurity? security,
        AccessControlSections sections, IDokanFileInfo info)
    {
        security = null;
        return DokanResult.AccessDenied;
    }

    public NtStatus SetFileSecurity(string fileName, FileSystemSecurity security,
        AccessControlSections sections, IDokanFileInfo info)
        => DokanResult.AccessDenied;

    public NtStatus Mounted(string mountPoint, IDokanFileInfo info) => DokanResult.Success;
    public NtStatus Unmounted(IDokanFileInfo info) => DokanResult.Success;

    public NtStatus FindStreams(string fileName, out IList<FileInformation> streams, IDokanFileInfo info)
    {
        streams = [];
        return DokanResult.NotImplemented;
    }

    public NtStatus SetFileAttributes(string fileName, FileAttributes attributes, IDokanFileInfo info)
        => DokanResult.Success;

    public NtStatus SetFileTime(string fileName, DateTime? creationTime, DateTime? lastAccessTime,
        DateTime? lastWriteTime, IDokanFileInfo info)
        => DokanResult.Success;

    public NtStatus LockFile(string fileName, long offset, long length, IDokanFileInfo info)
        => DokanResult.Success;

    public NtStatus UnlockFile(string fileName, long offset, long length, IDokanFileInfo info)
        => DokanResult.Success;

    // ====================================================================
    // 内部ヘルパー
    // ====================================================================

    private void UploadWriteState(WriteState ws)
    {
        byte[] plainData = ws.GetFinalData();
        if (plainData.Length == 0 && ws.CurrentSize == 0)
            return;

        // 非E2EE モード: 平文アップロード
        if (!_isE2ee)
        {
            try
            {
                CistaNasApiClientFiles.UploadFileAsync(_api, _volumeName, ws.PlainName, plainData).GetAwaiter().GetResult();

                // 旧ファイルの削除（上書きの場合）
                if (ws.ExistingFileId is not null)
                {
                    try
                    {
                        CistaNasApiClientFiles.DeleteFileAsync(_api, _volumeName, ws.ExistingFileId).GetAwaiter().GetResult();
                    }
                    catch { /* ベストエフォート: 孤児は許容 */ }
                }

                _listingCache.Invalidate();
                lock (_statsLock) { _cachedStats = null; }
            }
            catch
            {
                // エラーを無視（Cleanup は void）
            }
            return;
        }

        // E2EE モード: ファイル名暗号化 + チャンク暗号化
        string encName = E2eeCrypto.EncryptFilename(ws.PlainName, _masterKey!);
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(_masterKey!, fileSalt);

        int plainLength = plainData.Length;
        int chunkCount = plainLength == 0 ? 0 : (plainLength + _chunkSize - 1) / _chunkSize;
        if (chunkCount == 0) chunkCount = 1;

        long encLength = 16L + plainLength + (long)chunkCount * 16;
        string fileId = _api.CreateFileAsync(_volumeName, encName, encLength, chunkCount).GetAwaiter().GetResult();

        int written = 0;
        for (int i = 0; i < chunkCount; i++)
        {
            int chunkLen = Math.Min(_chunkSize, plainLength - written);
            byte[] chunk = new byte[chunkLen];
            Buffer.BlockCopy(plainData, written, chunk, 0, chunkLen);

            byte[] encChunk = E2eeCrypto.EncryptChunk(chunk, fileKey, i, fileSalt, isFirstChunk: i == 0);
            _api.UploadChunkAsync(_volumeName, fileId, i, encChunk).GetAwaiter().GetResult();
            written += chunkLen;
        }

        _api.FinalizeFileAsync(_volumeName, fileId, encLength).GetAwaiter().GetResult();

        // 旧ファイルの削除（上書きの場合）
        if (ws.ExistingFileId is not null)
        {
            try
            {
                _api.DeleteFileAsync(_volumeName, ws.ExistingFileId).GetAwaiter().GetResult();
                _cache.TryRemove(ws.ExistingFileId, out _);
            }
            catch { /* ベストエフォート: 孤児は許容 */ }
        }

        // キャッシュ更新
        _fileIdCache[ws.PlainName] = fileId;
        _cache[fileId] = new FileCache
        {
            PlainName = ws.PlainName,
            FileId = fileId,
            ChunkCount = chunkCount,
            EncryptedLength = encLength,
            PlainLength = plainLength,
        };
        _listingCache.Invalidate();
        lock (_statsLock) { _cachedStats = null; } // 使用量が変わったので再取得
    }

    private string? FindFileId(string plainName)
    {
        if (_fileIdCache.TryGetValue(plainName, out var fileId))
            return fileId;

        try
        {
            // キャッシュミス: 一覧を取得して名前インデックスを構築
            var entries = _api.ListFilesAsync(_volumeName).GetAwaiter().GetResult();
            foreach (var entry in entries)
            {
                string decrypted = E2eeCrypto.DecryptFilename(entry.EncryptedName, _masterKey!);
                _fileIdCache.TryAdd(decrypted, entry.FileId);
            }
            return _fileIdCache.TryGetValue(plainName, out var found) ? found : null;
        }
        catch { }

        return null;
    }

    private FileCache? GetOrCreateCache(string fileId)
    {
        if (_cache.TryGetValue(fileId, out var c)) return c;

        try
        {
            var entries = _api.ListFilesAsync(_volumeName).GetAwaiter().GetResult();
            foreach (var entry in entries)
            {
                if (entry.FileId == fileId)
                {
                    string plainName = E2eeCrypto.DecryptFilename(entry.EncryptedName, _masterKey);
                    long plainLength = Math.Max(0, entry.EncryptedLength - 16L - (long)entry.ChunkCount * 16);
                    var cache = new FileCache
                    {
                        PlainName = plainName,
                        FileId = fileId,
                        ChunkCount = entry.ChunkCount,
                        EncryptedLength = entry.EncryptedLength,
                        PlainLength = plainLength,
                    };
                    _cache[fileId] = cache;
                    _fileIdCache[plainName] = fileId;
                    return cache;
                }
            }
        }
        catch { }

        return null;
    }

    private static bool IsMatch(string name, string pattern)
    {
        if (pattern == "*") return true;
        try { return System.Text.RegularExpressions.Regex.IsMatch(name, WildcardToRegex(pattern)); }
        catch { return false; }
    }

    private (long UserUsedBytes, long UserQuotaBytes) GetOrRefreshStats()
    {
        lock (_statsLock)
        {
            if (_cachedStats is not null) return _cachedStats.Value;

            // 非E2EE モード: ディスク容量は無制限
            if (!_isE2ee)
            {
                const long unlimited = 100L * 1024 * 1024 * 1024 * 1024; // 100 TB
                _cachedStats = (0, unlimited);
                return _cachedStats.Value;
            }

            // E2EE モード: API から取得
            try
            {
                var stats = _api.GetVolumeStatsAsync(_volumeName).GetAwaiter().GetResult();
                var result = (stats.UserUsedBytes, stats.UserQuotaBytes);
                _cachedStats = result;
                return result;
            }
            catch
            {
                // API 取得失敗時は無制限を返す
                return (0, 0);
            }
        }
    }

    private static string WildcardToRegex(string pattern)
        => "^" + System.Text.RegularExpressions.Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
}
