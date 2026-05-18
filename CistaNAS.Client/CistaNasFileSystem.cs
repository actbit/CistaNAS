using System.Security.AccessControl;
using CistaNAS.Client.Api;
using CistaNAS.Client.Crypto;
using DokanNet;

namespace CistaNAS.Client;

/// <summary>
/// Dokan ベースの仮想ファイルシステム。
/// CistaNAS の E2EE ボリュームを Windows エクスプローラーにマウントする。
/// </summary>
public sealed class CistaNasFileSystem : IDokanOperations
{
    private readonly CistaNasApiClient _api;
    private readonly byte[] _masterKey;
    private readonly string _volumeName;
    private readonly int _chunkSize;

    private readonly Dictionary<string, FileCache> _cache = new(StringComparer.Ordinal);

    public CistaNasFileSystem(CistaNasApiClient api, byte[] masterKey, string volumeName, int chunkSize = 1048576)
    {
        _api = api;
        _masterKey = masterKey;
        _volumeName = volumeName;
        _chunkSize = chunkSize;
    }

    private sealed class FileCache
    {
        public string PlainName = "";
        public int ChunkCount;
        public long EncryptedLength;
        public Dictionary<int, byte[]> DecryptedChunks = new();
    }

    public void Cleanup(string fileName, IDokanFileInfo info) { }
    public void CloseFile(string fileName, IDokanFileInfo info) { }

    public NtStatus CreateFile(string fileName, DokanNet.FileAccess access, FileShare share,
        FileMode mode, FileOptions options, FileAttributes attributes, IDokanFileInfo info)
    {
        if (mode == FileMode.Open || mode == FileMode.OpenOrCreate)
        {
            if (fileName == "\\")
            {
                info.IsDirectory = true;
                return DokanResult.Success;
            }

            var fileId = FindFileId(fileName.TrimStart('\\'));
            if (fileId is not null)
            {
                info.Context = fileId;
                return DokanResult.Success;
            }
            if (mode == FileMode.OpenOrCreate)
            {
                info.Context = fileName.TrimStart('\\');
                return DokanResult.Success;
            }
            return DokanResult.FileNotFound;
        }

        if (mode == FileMode.CreateNew || mode == FileMode.Create)
        {
            info.Context = fileName.TrimStart('\\');
            return DokanResult.Success;
        }

        return DokanResult.Success;
    }

    public NtStatus ReadFile(string fileName, byte[] buffer, out int bytesRead, long offset, IDokanFileInfo info)
    {
        bytesRead = 0;
        string? fileId = info.Context as string;
        if (fileId is null) return DokanResult.FileNotFound;

        var cache = GetOrCreateCache(fileId);
        if (cache is null) return DokanResult.FileNotFound;

        long fileOffset = 0;
        for (int i = 0; i < cache.ChunkCount && bytesRead < buffer.Length; i++)
        {
            if (!cache.DecryptedChunks.TryGetValue(i, out var chunk))
            {
                try
                {
                    var encData = _api.DownloadChunkAsync(_volumeName, fileId, i).GetAwaiter().GetResult();
                    // 最初は salt なしで試行、失敗したら salt 抽出してリトライ
                    byte[] fileKey = E2eeCrypto.DeriveFileKey(_masterKey, []);
                    try
                    {
                        chunk = E2eeCrypto.DecryptChunk(encData, fileKey, i, out var salt);
                        if (salt.Length > 0)
                        {
                            fileKey = E2eeCrypto.DeriveFileKey(_masterKey, salt);
                            chunk = E2eeCrypto.DecryptChunk(encData, fileKey, i, out _);
                        }
                    }
                    catch
                    {
                        // salt を最初のチャンクから抽出
                        if (i == 0 && encData.Length > 16)
                        {
                            byte[] salt = new byte[16];
                            Buffer.BlockCopy(encData, 0, salt, 0, 16);
                            fileKey = E2eeCrypto.DeriveFileKey(_masterKey, salt);
                            chunk = E2eeCrypto.DecryptChunk(encData, fileKey, i, out _);
                        }
                        else throw;
                    }
                    cache.DecryptedChunks[i] = chunk;
                }
                catch
                {
                    return DokanResult.InternalError;
                }
            }

            long chunkStart = fileOffset;
            long chunkEnd = chunkStart + chunk.Length;

            if (offset < chunkEnd && offset + bytesRead < chunkEnd)
            {
                int copyOffset = (int)Math.Max(0, offset - chunkStart);
                int copyLen = Math.Min(chunk.Length - copyOffset, buffer.Length - bytesRead);
                Buffer.BlockCopy(chunk, copyOffset, buffer, bytesRead, copyLen);
                bytesRead += copyLen;
            }

            fileOffset += chunk.Length;
        }

        return DokanResult.Success;
    }

    public NtStatus WriteFile(string fileName, byte[] buffer, out int bytesWritten, long offset, IDokanFileInfo info)
    {
        bytesWritten = 0;
        string? context = info.Context as string;
        if (context is null) return DokanResult.FileNotFound;

        try
        {
            string plainName = context;
            string encName = E2eeCrypto.EncryptFilename(plainName, _masterKey);
            byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
            byte[] fileKey = E2eeCrypto.DeriveFileKey(_masterKey, fileSalt);

            int chunkCount = (buffer.Length + _chunkSize - 1) / _chunkSize;
            if (chunkCount == 0) chunkCount = 1;

            long encLength = fileSalt.Length + (long)chunkCount * (_chunkSize + 16);
            string fileId = _api.CreateFileAsync(_volumeName, encName, encLength, chunkCount).GetAwaiter().GetResult();

            int written = 0;
            for (int i = 0; i < chunkCount; i++)
            {
                int chunkLen = Math.Min(_chunkSize, buffer.Length - written);
                byte[] chunk = new byte[chunkLen];
                Buffer.BlockCopy(buffer, written, chunk, 0, chunkLen);

                byte[] encChunk = E2eeCrypto.EncryptChunk(chunk, fileKey, i, fileSalt, isFirstChunk: i == 0);
                _api.UploadChunkAsync(_volumeName, fileId, i, encChunk).GetAwaiter().GetResult();
                written += chunkLen;
            }

            _api.FinalizeFileAsync(_volumeName, fileId, written).GetAwaiter().GetResult();
            bytesWritten = buffer.Length;
            return DokanResult.Success;
        }
        catch
        {
            return DokanResult.InternalError;
        }
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

        var fileId = FindFileId(fileName.TrimStart('\\'));
        if (fileId is null) return DokanResult.FileNotFound;

        var cache = GetOrCreateCache(fileId);
        if (cache is not null)
        {
            fileInfo.Length = cache.EncryptedLength;
            fileInfo.FileName = cache.PlainName;
        }

        return DokanResult.Success;
    }

    public NtStatus FindFiles(string fileName, out IList<FileInformation> files, IDokanFileInfo info)
    {
        files = new List<FileInformation>();
        try
        {
            var entries = _api.ListFilesAsync(_volumeName).GetAwaiter().GetResult();
            foreach (var entry in entries)
            {
                string plainName = E2eeCrypto.DecryptFilename(entry.EncryptedName, _masterKey);
                files.Add(new FileInformation
                {
                    FileName = plainName,
                    Attributes = FileAttributes.Normal,
                    Length = entry.EncryptedLength,
                    CreationTime = entry.CreatedAt.DateTime,
                    LastWriteTime = entry.ModifiedAt.DateTime,
                });
            }
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
        var fileId = FindFileId(fileName.TrimStart('\\'));
        if (fileId is null) return DokanResult.FileNotFound;
        _api.DeleteFileAsync(_volumeName, fileId).GetAwaiter().GetResult();
        _cache.Remove(fileId);
        return DokanResult.Success;
    }

    public NtStatus DeleteDirectory(string fileName, IDokanFileInfo info) => DokanResult.Success;

    public NtStatus MoveFile(string oldName, string newName, bool replace, IDokanFileInfo info)
        => DokanResult.NotImplemented;

    public NtStatus GetDiskFreeSpace(out long freeBytesAvailable, out long totalNumberOfBytes,
        out long totalNumberOfFreeBytes, IDokanFileInfo info)
    {
        freeBytesAvailable = 0;
        totalNumberOfBytes = 0;
        totalNumberOfFreeBytes = 0;
        return DokanResult.Success;
    }

    public NtStatus GetVolumeInformation(out string volumeName, out FileSystemFeatures features,
        out string fileSystemName, out uint maximumComponentLength, IDokanFileInfo info)
    {
        volumeName = "CistaNAS E2EE";
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

    public NtStatus SetEndOfFile(string fileName, long length, IDokanFileInfo info)
        => DokanResult.NotImplemented;

    public NtStatus SetAllocationSize(string fileName, long length, IDokanFileInfo info)
        => DokanResult.NotImplemented;

    public NtStatus SetFileAttributes(string fileName, FileAttributes attributes, IDokanFileInfo info)
        => DokanResult.Success;

    public NtStatus SetFileTime(string fileName, DateTime? creationTime, DateTime? lastAccessTime,
        DateTime? lastWriteTime, IDokanFileInfo info)
        => DokanResult.Success;

    public NtStatus LockFile(string fileName, long offset, long length, IDokanFileInfo info)
        => DokanResult.Success;

    public NtStatus UnlockFile(string fileName, long offset, long length, IDokanFileInfo info)
        => DokanResult.Success;

    // ---- 内部 ----

    private string? FindFileId(string plainName)
    {
        try
        {
            var entries = _api.ListFilesAsync(_volumeName).GetAwaiter().GetResult();
            foreach (var entry in entries)
            {
                string decrypted = E2eeCrypto.DecryptFilename(entry.EncryptedName, _masterKey);
                if (string.Equals(decrypted, plainName, StringComparison.OrdinalIgnoreCase))
                    return entry.FileId;
            }
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
                    var cache = new FileCache
                    {
                        PlainName = E2eeCrypto.DecryptFilename(entry.EncryptedName, _masterKey),
                        ChunkCount = entry.ChunkCount,
                        EncryptedLength = entry.EncryptedLength,
                    };
                    _cache[fileId] = cache;
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

    private static string WildcardToRegex(string pattern)
        => "^" + System.Text.RegularExpressions.Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
}
