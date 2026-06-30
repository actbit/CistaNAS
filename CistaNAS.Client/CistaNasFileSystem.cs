using System.Collections.Concurrent;
using System.Security.AccessControl;
using System.Security.Cryptography;
using CistaNAS.Client.Api;
using CistaNAS.Client.Security;
using CistaNAS.Shared.Crypto;
using DokanNet;

namespace CistaNAS.Client;

/// <summary>
/// Dokan ベースの仮想ファイルシステム。
/// CistaNAS のボリューム（E2EE/非E2EE両対応）を Windows エクスプローラーにマウントする。
/// </summary>
public sealed class CistaNasFileSystem : IDokanOperations, IDisposable
{
    private readonly CistaNasApiClient _api;
    private readonly SecureBuffer? _masterKey;  // E2EE モードでのみ使用（VirtualLock + ゼロクリア保護）
    private readonly string _volumeName;
    private readonly int _chunkSize;
    private readonly bool _isE2ee;  // E2EE モードフラグ

    // Level 1: plainName → fileId（E2EEのみ）
    private readonly ConcurrentDictionary<string, string> _fileIdCache = new(StringComparer.OrdinalIgnoreCase);

    // Level 2: fileId → FileCache（E2EEのみ、メタデータ + fileKey）
    private readonly ConcurrentDictionary<string, FileCache> _cache = new(StringComparer.Ordinal);

    // グローバルチャンクプール: 全ファイル合計20チャンク上限（ハッシュ検証付き）
    private readonly Dictionary<(string FileId, int ChunkIndex), (byte[] Data, string EncryptedHash)> _chunkPool = new();
    private readonly LinkedList<(string FileId, int ChunkIndex)> _chunkLru = new();
    private readonly object _chunkPoolLock = new();
    private const int MaxGlobalChunks = 20;

    // Level 3: ファイル一覧キャッシュ（TTL ベース）
    private readonly ListingCache _listingCache = new();

    // クオータ統計キャッシュ（Write/Delete 後に無効化）
    private (long UserUsedBytes, long UserQuotaBytes)? _cachedStats;
    private readonly object _statsLock = new();

    /// <summary>E2EE モードでファイルシステムを作成。</summary>
    public CistaNasFileSystem(CistaNasApiClient api, byte[] masterKey, string volumeName, int chunkSize = 1048576)
    {
        _api = api;
        _masterKey = new SecureBuffer(masterKey);
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

    // ---- 内部クラス: ファイルキャッシュ（メタデータ + fileKey のみ。チャンクはグローバルプールで管理） ----

    internal sealed class FileCache
    {
        public string PlainName = "";
        public string FileId = "";
        public int ChunkCount;
        public long PlainLength;

        private byte[]? _fileKey;
        private byte[]? _fileSalt;
        private readonly object _fileKeyLock = new();

        /// <summary>FileKey と fileSalt をスレッドセーフに設定。上書き可能（他クライアントの上書きで salt が変わった場合に再導出が必要）。</summary>
        public void SetFileKey(byte[] key, byte[] salt)
        {
            lock (_fileKeyLock)
            {
                _fileKey = key;
                _fileSalt = salt;
            }
        }

        /// <summary>FileKey と fileSalt が設定されているか確認し、設定されていれば返す。</summary>
        public bool TryGetFileKey(out byte[]? key, out byte[]? salt)
        {
            lock (_fileKeyLock)
            {
                key = _fileKey;
                salt = _fileSalt;
                return _fileKey is not null;
            }
        }

        /// <summary>FileKey と fileSalt をゼロクリア（アンマウント時）。</summary>
        public void Dispose()
        {
            lock (_fileKeyLock)
            {
                if (_fileKey is not null) CryptographicOperations.ZeroMemory(_fileKey);
                if (_fileSalt is not null) CryptographicOperations.ZeroMemory(_fileSalt);
                _fileKey = null;
                _fileSalt = null;
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

    // ---- 内部クラス: 書き込み状態（チャンクベース差分保存） ----

    internal abstract class WriteState
    {
        public readonly string PlainName;
        public readonly string? ExistingFileId; // 上書き時の旧ファイルID（E2EE は fileId、非E2EE は plainName または null）
        protected readonly CistaNasFileSystem Fs;
        public long DeclaredSize = -1; // SetEndOfFile で指定されたサイズ

        protected WriteState(CistaNasFileSystem fs, string plainName, string? existingFileId)
        {
            Fs = fs;
            PlainName = plainName;
            ExistingFileId = existingFileId;
        }

        public abstract long CurrentSize { get; }
        public abstract void Write(byte[] data, int dataOffset, int count, long fileOffset);
        public abstract void SetDeclaredSize(long size);

        /// <summary>機密データ（ファイルキー、平文チャンク等）をゼロクリア。Cleanup/アンマウント時に呼ぶ。</summary>
        public virtual void Dispose() { }
    }

    // 非 E2EE: 汚れたバイト範囲を記録し、Cleanup で PATCH（部分書き込み）する。RMW 不要（サーバー AesXtsStream が処理）。
    internal sealed class PlainRangeWriteState : WriteState
    {
        private readonly List<(long Offset, byte[] Data)> _ranges = new();
        private long _maxWritten;
        private readonly long _existingLength;

        public PlainRangeWriteState(CistaNasFileSystem fs, string plainName, string? existingFileId, long existingLength = 0)
            : base(fs, plainName, existingFileId)
        {
            _existingLength = existingLength;
        }

        public IReadOnlyList<(long Offset, byte[] Data)> Ranges => _ranges;

        public override long CurrentSize
        {
            get
            {
                long basis = Math.Max(_maxWritten, _existingLength);
                return DeclaredSize >= 0 ? Math.Max(DeclaredSize, basis) : basis;
            }
        }

        public override void Write(byte[] data, int dataOffset, int count, long fileOffset)
        {
            if (count <= 0) return;
            byte[] copy = new byte[count];
            Buffer.BlockCopy(data, dataOffset, copy, 0, count);
            _ranges.Add((fileOffset, copy));
            long end = fileOffset + count;
            if (end > _maxWritten) _maxWritten = end;
        }

        public override void SetDeclaredSize(long size)
        {
            DeclaredSize = size;
            if (size > _maxWritten) _maxWritten = size;
        }

        // 平文バッファをゼロクリア
        public override void Dispose()
        {
            foreach (var (_, data) in _ranges)
                CryptographicOperations.ZeroMemory(data);
            _ranges.Clear();
        }
    }

    // E2EE: 汚れたチャンクを RMW（既存チャンク DL→復号→部分更新）で追跡し、Cleanup で汚れたチャンクだけ差分上書きする。
    internal sealed class E2eeChunkWriteState : WriteState
    {
        private readonly Dictionary<int, byte[]> _dirtyChunks = new();
        private long _maxWritten;
        private byte[]? _existingFileSalt;
        private byte[]? _existingFileKey;
        private int _existingChunkCount;
        private long _existingPlainLength;

        public E2eeChunkWriteState(CistaNasFileSystem fs, string plainName, string? existingFileId)
            : base(fs, plainName, existingFileId)
        {
            if (existingFileId is not null)
            {
                var cache = fs.GetOrCreateCache(existingFileId);
                if (cache is not null)
                {
                    _existingChunkCount = cache.ChunkCount;
                    _existingPlainLength = cache.PlainLength;
                    if (cache.TryGetFileKey(out var key, out var salt))
                    {
                        _existingFileKey = key;
                        _existingFileSalt = salt;
                    }
                    else if (_existingChunkCount > 0)
                    {
                        // fileKey 未設定 → chunk0 の salt から導出（差分保存の RMW で既存チャンク復号に必要）
                        try
                        {
                            var (enc0, _) = fs._api.DownloadChunkAsync(fs._volumeName, existingFileId, 0).GetAwaiter().GetResult();
                            if (enc0.Length > E2eeCrypto.SaltSize)
                            {
                                var salt0 = new byte[E2eeCrypto.SaltSize];
                                Buffer.BlockCopy(enc0, 0, salt0, 0, E2eeCrypto.SaltSize);
                                _existingFileKey = E2eeCrypto.DeriveFileKey(fs._masterKey!.Buffer, salt0);
                                _existingFileSalt = salt0;
                                cache.SetFileKey(_existingFileKey, _existingFileSalt);
                            }
                        }
                        catch { /* ベストエフォート: 導出失敗時は新規チャンク扱い */ }
                    }
                }
            }
        }

        public IReadOnlyDictionary<int, byte[]> DirtyChunks => _dirtyChunks;
        public byte[]? ExistingFileSalt => _existingFileSalt;
        public byte[]? ExistingFileKey => _existingFileKey;
        public int ExistingChunkCount => _existingChunkCount;
        public long ExistingPlainLength => _existingPlainLength;

        public override long CurrentSize
        {
            get
            {
                if (DeclaredSize >= 0) return Math.Max(DeclaredSize, _maxWritten);
                return Math.Max(_maxWritten, ExistingFileId is not null ? _existingPlainLength : 0);
            }
        }

        public override void Write(byte[] data, int dataOffset, int count, long fileOffset)
        {
            if (count <= 0) return;
            int chunkSize = Fs._chunkSize;
            long endOffset = fileOffset + count;
            int startChunk = (int)(fileOffset / chunkSize);
            int endChunk = (int)((endOffset - 1) / chunkSize);

            for (int ci = startChunk; ci <= endChunk; ci++)
            {
                long chunkStart = (long)ci * chunkSize;
                byte[] chunk = GetOrLoadChunk(ci);
                long relStart = Math.Max(0, fileOffset - chunkStart);
                long relEnd = Math.Min(chunk.Length, endOffset - chunkStart);
                int copyLen = (int)(relEnd - relStart);
                long srcStart = Math.Max(0, chunkStart - fileOffset);
                Buffer.BlockCopy(data, dataOffset + (int)srcStart, chunk, (int)relStart, copyLen);
                _dirtyChunks[ci] = chunk;
            }
            if (endOffset > _maxWritten) _maxWritten = endOffset;
        }

        public override void SetDeclaredSize(long size)
        {
            DeclaredSize = size;
            if (size > _maxWritten) _maxWritten = size;
        }

        // ファイルキー・salt・平文チャンクをゼロクリア
        public override void Dispose()
        {
            if (_existingFileKey is not null) CryptographicOperations.ZeroMemory(_existingFileKey);
            if (_existingFileSalt is not null) CryptographicOperations.ZeroMemory(_existingFileSalt);
            foreach (var (_, chunk) in _dirtyChunks)
                CryptographicOperations.ZeroMemory(chunk);
            _dirtyChunks.Clear();
        }

        private byte[] GetOrLoadChunk(int ci)
        {
            if (_dirtyChunks.TryGetValue(ci, out var cached)) return cached;

            int chunkSize = Fs._chunkSize;
            // 既存チャンク: DL + 復号（末尾保持のため RMW）
            if (ExistingFileId is not null && ci < _existingChunkCount
                && _existingFileKey is not null && _existingFileSalt is not null)
            {
                return Fs.LoadPlainChunkForWrite(ExistingFileId, ci, _existingFileKey, _existingFileSalt);
            }
            // 新規チャンク: chunkSize のゼロ
            return new byte[chunkSize];
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
                ws.Dispose(); // 機密データ（ファイルキー・平文チャンク）をゼロクリア
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

            // 非E2EE モード: 読み取りはファイルパス、書き込みアクセスは差分保存（PlainRangeWriteState）
            if (!_isE2ee)
            {
                if ((access & (DokanNet.FileAccess.WriteData | DokanNet.FileAccess.GenericWrite)) != 0)
                {
                    long existingLength = GetExistingPlainLength(plainName);
                    info.Context = new PlainRangeWriteState(this, plainName, plainName, existingLength);
                }
                else
                {
                    info.Context = plainName;
                }
                return DokanResult.Success;
            }

            // E2EE モード: fileId で管理
            var fileId = FindFileId(plainName);
            if (fileId is not null)
            {
                // 書き込みアクセスがある場合は上書きモード（チャンク差分保存）
                if ((access & (DokanNet.FileAccess.WriteData | DokanNet.FileAccess.GenericWrite)) != 0)
                {
                    info.Context = new E2eeChunkWriteState(this, plainName, fileId);
                    return DokanResult.Success;
                }
                info.Context = fileId;
                return DokanResult.Success;
            }

            if (mode == FileMode.OpenOrCreate)
            {
                info.Context = new E2eeChunkWriteState(this, plainName, null);
                return DokanResult.Success;
            }

            return DokanResult.FileNotFound;
        }

        if (mode == FileMode.CreateNew)
        {
            // 非E2EE モード: 新規作成
            if (!_isE2ee)
            {
                info.Context = new PlainRangeWriteState(this, plainName, null);
                return DokanResult.Success;
            }

            // E2EE モード
            var existing = FindFileId(plainName);
            if (existing is not null)
                return DokanResult.FileExists;

            info.Context = new E2eeChunkWriteState(this, plainName, null);
            return DokanResult.Success;
        }

        if (mode == FileMode.Create)
        {
            // Create: 既存ファイルを上書き

            // 非E2EE モード: 既存ファイル長を取得して末尾保持
            if (!_isE2ee)
            {
                long existingLength = GetExistingPlainLength(plainName);
                info.Context = new PlainRangeWriteState(this, plainName, plainName, existingLength);
                return DokanResult.Success;
            }

            // E2EE モード: 旧IDを保持（差分上書き時は維持、新規作成時は Cleanup で削除）
            var existing = FindFileId(plainName);
            info.Context = new E2eeChunkWriteState(this, plainName, existing);
            return DokanResult.Success;
        }

        return DokanResult.Success;
    }

    /// <summary>非E2EE: 既存ファイルの平文長を取得（差分保存で末尾保持のため）。</summary>
    private long GetExistingPlainLength(string plainName)
    {
        try
        {
            var entries = CistaNasApiClientFiles.ListFilesAsync(_api, _volumeName).GetAwaiter().GetResult();
            var e = entries.FirstOrDefault(x => string.Equals(x.Name, plainName, StringComparison.OrdinalIgnoreCase));
            return e?.Length ?? 0;
        }
        catch { return 0; }
    }

    /// <summary>書き込み中のハンドル（WriteState）からの読み込み: 書き込みバッファ（dirty）+ 既存をマージして返す。</summary>
    private NtStatus ReadFromWriteState(WriteState ws, byte[] buffer, out int bytesRead, long offset)
    {
        bytesRead = 0;
        try
        {
            int totalRead = Task.Run(async () =>
            {
                byte[] result = new byte[buffer.Length];
                int filled = 0;

                if (ws is PlainRangeWriteState plain)
                {
                    // 既存データ（サーバー Range）を下地にする
                    if (plain.ExistingFileId is not null)
                    {
                        try
                        {
                            var existing = await CistaNasApiClientFiles.DownloadFileRangeAsync(_api, _volumeName, ws.PlainName, offset, buffer.Length);
                            Array.Copy(existing, 0, result, 0, existing.Length);
                            filled = existing.Length;
                        }
                        catch { }
                    }
                    // dirty ranges で上書き
                    foreach (var (off, data) in plain.Ranges)
                    {
                        long overlapStart = Math.Max(off, offset);
                        long overlapEnd = Math.Min(off + data.Length, offset + buffer.Length);
                        if (overlapEnd > overlapStart)
                        {
                            int copyOff = (int)(overlapStart - offset);
                            int srcOff = (int)(overlapStart - off);
                            int copyLen = (int)(overlapEnd - overlapStart);
                            Array.Copy(data, srcOff, result, copyOff, copyLen);
                            filled = Math.Max(filled, copyOff + copyLen);
                        }
                    }
                }
                else if (ws is E2eeChunkWriteState e2ee)
                {
                    int chunkSize = _chunkSize;
                    int startChunk = (int)(offset / chunkSize);

                    for (int ci = startChunk; filled < buffer.Length; ci++)
                    {
                        long chunkStart = (long)ci * chunkSize;
                        if (chunkStart >= offset + buffer.Length) break;

                        byte[] chunk;
                        if (e2ee.DirtyChunks.TryGetValue(ci, out var dirty))
                        {
                            chunk = dirty;
                        }
                        else if (e2ee.ExistingFileId is not null && ci < e2ee.ExistingChunkCount
                                 && e2ee.ExistingFileKey is not null && e2ee.ExistingFileSalt is not null)
                        {
                            chunk = LoadPlainChunkForWrite(e2ee.ExistingFileId, ci, e2ee.ExistingFileKey, e2ee.ExistingFileSalt);
                        }
                        else
                        {
                            // 新規ファイルのギャップ or 既存超: ゼロチャンク
                            chunk = new byte[chunkSize];
                        }

                        int copyOff = (int)Math.Max(0, offset - chunkStart);
                        int maxCopy = Math.Min(chunk.Length - copyOff, buffer.Length - filled);
                        if (copyOff < chunk.Length && maxCopy > 0)
                        {
                            Array.Copy(chunk, copyOff, result, filled, maxCopy);
                            filled += maxCopy;
                        }
                    }
                }

                Array.Copy(result, 0, buffer, 0, filled);
                return filled;
            }).GetAwaiter().GetResult();

            bytesRead = totalRead;
            return DokanResult.Success;
        }
        catch
        {
            return DokanResult.InternalError;
        }
    }

    public NtStatus ReadFile(string fileName, byte[] buffer, out int bytesRead, long offset, IDokanFileInfo info)
    {
        bytesRead = 0;

        // 書き込み中のハンドル（WriteState）からの読み込み: 書き込みバッファ + 既存をマージして返す。
        // エディタが読み書き両用で開いた際、編集前/編集中の内容を読めるようにする。
        if (info.Context is WriteState ws)
            return ReadFromWriteState(ws, buffer, out bytesRead, offset);

        // 非E2EE モード: Range リクエストで必要な部分のみダウンロード
        if (!_isE2ee)
        {
            if (info.Context is not string filePath)
                return DokanResult.InvalidParameter;

            try
            {
                // Task.Run で別スレッドで非同期実行し、結果を待機
                var data = Task.Run(async () =>
                {
                    return await CistaNasApiClientFiles.DownloadFileRangeAsync(
                        _api, _volumeName, filePath, offset, buffer.Length);
                }).GetAwaiter().GetResult();

                Array.Copy(data, 0, buffer, 0, data.Length);
                bytesRead = data.Length;
                return DokanResult.Success;
            }
            catch
            {
                return DokanResult.InternalError;
            }
        }

        // E2EE モード: チャンクダウンロード + 復号化（ハッシュ検証付きキャッシュ）
        if (info.Context is not string fileId)
            return DokanResult.InvalidParameter;

        try
        {
            // Task.Run で別スレッドで非同期実行し、結果を待機
            var result = Task.Run(async () =>
            {
                int localBytesRead = 0;
                var cache = GetOrCreateCache(fileId);
                if (cache is null) return (DokanResult.FileNotFound, 0);

                // チャンク 0 から salt を抽出して fileKey を確定。
                // salt は全チャンクの nonce 導出（DeriveChunkNonce）で共通して使うため保持する。
                if (!cache.TryGetFileKey(out var fileKey, out var fileSalt))
                {
                    var (encData, rev0) = await _api.DownloadChunkAsync(_volumeName, fileId, 0);
                    if (encData.Length <= 16)
                        return (DokanResult.InternalError, 0);

                    fileSalt = new byte[16];
                    Buffer.BlockCopy(encData, 0, fileSalt, 0, 16);
                    var derivedKey = E2eeCrypto.DeriveFileKey(_masterKey!.Buffer, fileSalt);

                    // チャンク 0 を復号してキャッシュ
                    var chunk = E2eeCrypto.DecryptChunk(encData, derivedKey, 0, fileSalt, rev0);
                    PutChunkToPool(fileId, 0, chunk, ComputeHashHex(encData));

                    cache.SetFileKey(derivedKey, fileSalt);
                    fileKey = derivedKey;
                }

                // 他クライアント上書き検出のため、チャンク0のハッシュ検証を最初に行う
                // salt が変わった場合は fileKey を再導出する必要がある
                byte[]? fileKeyToUse = fileKey;
                var chunk0Cached = TryGetChunkFromPool(fileId, 0);
                if (chunk0Cached.HasValue)
                {
                    string? serverHash = null;
                    try
                    {
                        var (h0c, _) = await _api.GetChunkHashAsync(_volumeName, fileId, 0);
                        serverHash = h0c;
                    }
                    catch { /* 通信失敗時は後で再ダウンロード */ }

                    if (serverHash is null || serverHash != chunk0Cached.Value.EncryptedHash)
                    {
                        // チャンク0が変わっている可能性があるため、再ダウンロードして salt を確認
                        var (chunk0Data, chunk0Rev) = await _api.DownloadChunkAsync(_volumeName, fileId, 0);
                        if (chunk0Data.Length > E2eeCrypto.SaltSize)
                        {
                            byte[] newSalt = new byte[E2eeCrypto.SaltSize];
                            Buffer.BlockCopy(chunk0Data, 0, newSalt, 0, E2eeCrypto.SaltSize);
                            var newKey = E2eeCrypto.DeriveFileKey(_masterKey!.Buffer, newSalt);

                            // fileKey が変わった場合はキャッシュをクリアして再構築
                            if (newKey != fileKey)
                            {
                                cache.SetFileKey(newKey, newSalt);
                                fileKeyToUse = newKey;
                                fileSalt = newSalt;
                                RemoveFileChunksFromPool(fileId);

                                // チャンク0を復号してキャッシュ
                                var chunk0 = E2eeCrypto.DecryptChunk(chunk0Data, newKey, 0, newSalt, chunk0Rev);
                                PutChunkToPool(fileId, 0, chunk0, ComputeHashHex(chunk0Data));
                            }
                        }
                    }
                }

                // シーク最適化: offset から開始チャンクを計算
                int startChunk = cache.ChunkCount > 0
                    ? Math.Min((int)(offset / _chunkSize), cache.ChunkCount - 1)
                    : 0;
                long fileOffset = (long)startChunk * _chunkSize;

                for (int i = startChunk; i < cache.ChunkCount && localBytesRead < buffer.Length; i++)
                {
                    if (offset + localBytesRead >= cache.PlainLength)
                        break;

                    byte[] chunk;

                    // キャッシュヒット: ハッシュ検証で鮮度確認
                    var cached = TryGetChunkFromPool(fileId, i);
                    if (cached.HasValue)
                    {
                        string? serverHash = null;
                        try
                        {
                            var (hi, _) = await _api.GetChunkHashAsync(_volumeName, fileId, i);
                            serverHash = hi;
                        }
                        catch
                        {
                            // ハッシュ検証の通信失敗時はキャッシュを信頼せず再ダウンロード
                        }

                        if (serverHash is not null && serverHash == cached.Value.EncryptedHash)
                        {
                            // ハッシュ一致 → キャッシュ利用
                            chunk = cached.Value.Data;
                        }
                        else
                        {
                            // ハッシュ不一致 or ハッシュなし or 通信失敗 → 再ダウンロード
                            var (encData, rev) = await _api.DownloadChunkAsync(_volumeName, fileId, i);
                            chunk = E2eeCrypto.DecryptChunk(encData, fileKeyToUse!, i, fileSalt!, rev);
                            PutChunkToPool(fileId, i, chunk, ComputeHashHex(encData));
                        }
                    }
                    else
                    {
                        // キャッシュミス: ダウンロード + 復号 + キャッシュ保存
                        var (encData, rev) = await _api.DownloadChunkAsync(_volumeName, fileId, i);
                        chunk = E2eeCrypto.DecryptChunk(encData, fileKeyToUse!, i, fileSalt!, rev);
                        PutChunkToPool(fileId, i, chunk, ComputeHashHex(encData));
                    }

                    long chunkStart = fileOffset;
                    long chunkEnd = chunkStart + chunk.Length;

                    if (offset < chunkEnd)
                    {
                        int copyOffset = (int)Math.Max(0, offset - chunkStart);
                        int maxCopy = Math.Min(chunk.Length - copyOffset, buffer.Length - localBytesRead);
                        if (offset + localBytesRead + maxCopy > cache.PlainLength)
                            maxCopy = (int)Math.Max(0, cache.PlainLength - offset - localBytesRead);
                        if (maxCopy > 0)
                        {
                            Buffer.BlockCopy(chunk, copyOffset, buffer, localBytesRead, maxCopy);
                            localBytesRead += maxCopy;
                        }
                    }

                    fileOffset += chunk.Length;
                }

                return (DokanResult.Success, localBytesRead);
            }).GetAwaiter().GetResult();

            bytesRead = result.Item2;
            return result.Item1;
        }
        catch
        {
            bytesRead = 0;
            return DokanResult.InternalError;
        }
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
                try { plainName = E2eeCrypto.DecryptFilename(entry.EncryptedName, _masterKey!.Buffer); }
                catch { plainName = $"<{entry.FileId[..8]}...>"; }

                long plainLength = Math.Max(0, entry.EncryptedLength - E2eeCrypto.SaltSize - (long)entry.ChunkCount * E2eeCrypto.GcmTagSize);

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
        RemoveFileChunksFromPool(fileId);
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

    internal void UploadWriteState(WriteState ws)
    {
        // 例外はそのまま上位（Cleanup）に伝播させる。Cleanup が void 制約でエラーを飲む。
        switch (ws)
        {
            case PlainRangeWriteState plain:
                UploadPlain(plain);
                break;
            case E2eeChunkWriteState e2ee:
                if (e2ee.ExistingFileId is null)
                    UploadE2eeNewFile(e2ee);
                else
                    UploadE2eeDiff(e2ee);
                break;
        }

        _listingCache.Invalidate();
        lock (_statsLock) { _cachedStats = null; }
    }

    // 非E2EE: 汚れた範囲を PATCH（差分保存）。Critical-3 と同様、DELETE は呼ばない。
    private void UploadPlain(PlainRangeWriteState ws)
    {
        bool isNew = ws.ExistingFileId is null;

        // 新規ファイルで offset=0 から始まらない（sparse）または空の場合は全体アップロードで確実に作成。
        if (isNew && (ws.Ranges.Count == 0 || ws.Ranges[0].Offset != 0))
        {
            long size = ws.CurrentSize;
            byte[] full = new byte[Math.Max(0, size)];
            foreach (var (off, data) in ws.Ranges)
            {
                if (off >= 0 && off + data.Length <= full.Length)
                    Buffer.BlockCopy(data, 0, full, (int)off, data.Length);
            }
            CistaNasApiClientFiles.UploadFileAsync(_api, _volumeName, ws.PlainName, full).GetAwaiter().GetResult();
            return;
        }

        if (ws.Ranges.Count == 0)
        {
            // 既存ファイルで書き込みなし → 何もしない
            return;
        }

        // 各範囲を PATCH（サーバー AesXtsStream がセクタ RMW で安全に部分上書き）
        foreach (var (off, data) in ws.Ranges)
        {
            CistaNasApiClientFiles.PatchFileRangeAsync(_api, _volumeName, ws.PlainName, off, data).GetAwaiter().GetResult();
        }
    }

    // E2EE 新規ファイル: 新 fileSalt で全チャンク作成（従来方式、Critical-4 ロールバック維持）。
    private void UploadE2eeNewFile(E2eeChunkWriteState ws)
    {
        string encName = E2eeCrypto.EncryptFilename(ws.PlainName, _masterKey!.Buffer);
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(_masterKey!.Buffer, fileSalt);

        long plainLength = ws.CurrentSize;
        int chunkCount = plainLength == 0 ? 1 : (int)((plainLength + _chunkSize - 1) / _chunkSize);
        long encLength = 16L + plainLength + (long)chunkCount * 16;
        string fileId = _api.CreateFileAsync(_volumeName, encName, encLength, chunkCount).GetAwaiter().GetResult();

        bool finalized = false;
        try
        {
            long written = 0;
            for (int i = 0; i < chunkCount; i++)
            {
                int chunkLen = (int)Math.Min(_chunkSize, plainLength - written);
                byte[] chunk;
                if (ws.DirtyChunks.TryGetValue(i, out var dirty))
                {
                    chunk = new byte[chunkLen];
                    Array.Copy(dirty, chunk, Math.Min(dirty.Length, chunkLen));
                }
                else
                {
                    chunk = new byte[chunkLen]; // ゼロ
                }
                byte[] encChunk = E2eeCrypto.EncryptChunk(chunk, fileKey, i, fileSalt, isFirstChunk: i == 0);
                _api.UploadChunkAsync(_volumeName, fileId, i, encChunk).GetAwaiter().GetResult();
                written += chunkLen;
            }
            _api.FinalizeFileAsync(_volumeName, fileId, encLength).GetAwaiter().GetResult();
            finalized = true;
        }
        catch
        {
            // ロールバック: 作成中の fileId を削除し、サーバーに孤児ファイルを残さない（Critical-4）。
            try { _api.DeleteFileAsync(_volumeName, fileId).GetAwaiter().GetResult(); }
            catch { /* ベストエフォート */ }
            throw;
        }

        if (finalized)
        {
            _fileIdCache[ws.PlainName] = fileId;
            _cache[fileId] = new FileCache
            {
                PlainName = ws.PlainName,
                FileId = fileId,
                ChunkCount = chunkCount,
                PlainLength = plainLength,
            };
        }
    }

    // E2EE 既存ファイル差分: 汚れたチャンクだけ再暗号化（revision+1）して差分上書き。fileSalt/fileKey は維持。
    private void UploadE2eeDiff(E2eeChunkWriteState ws)
    {
        string fileId = ws.ExistingFileId!;
        byte[] fileSalt = ws.ExistingFileSalt!;
        byte[] fileKey = ws.ExistingFileKey!;

        long newPlainLength = ws.CurrentSize;
        int newChunkCount = newPlainLength == 0 ? 0 : (int)((newPlainLength + _chunkSize - 1) / _chunkSize);

        // 汚れたチャンクだけ再暗号化して replace（未変更チャンクは維持 → 末尾保持）。
        foreach (var (ci, chunk) in ws.DirtyChunks)
        {
            if (ci >= newChunkCount) continue; // 縮小で不要になったチャンクは送らない
            int chunkLen = (int)Math.Min(_chunkSize, newPlainLength - (long)ci * _chunkSize);
            byte[] toEncrypt = chunk.Length == chunkLen ? chunk : ResizeChunk(chunk, chunkLen);

            // 現在 revision を取得し +1 で暗号化（AES-GCM の nonce 再利用回避）
            int currentRev = 0;
            try { var (_, rev) = _api.GetChunkHashAsync(_volumeName, fileId, ci).GetAwaiter().GetResult(); currentRev = rev; }
            catch { }

            byte[] encChunk = E2eeCrypto.EncryptChunk(toEncrypt, fileKey, ci, fileSalt, isFirstChunk: ci == 0, revision: currentRev + 1);
            _api.UploadChunkAsync(_volumeName, fileId, ci, encChunk, replace: true).GetAwaiter().GetResult();

            // チャンクプールのキャッシュを更新（新しい暗号文ハッシュで）
            PutChunkToPool(fileId, ci, toEncrypt, ComputeHashHex(encChunk));
        }

        // FinalizeFile で長さ確定（縮小時は ChunkCount 指定で論理切り詰め）
        int finalizeChunkCount = Math.Max(1, newChunkCount);
        long encLength = 16L + newPlainLength + (long)finalizeChunkCount * 16;
        int? chunkCountParam = newChunkCount < ws.ExistingChunkCount ? newChunkCount : null;
        _api.FinalizeFileAsync(_volumeName, fileId, encLength, chunkCountParam).GetAwaiter().GetResult();

        // キャッシュ更新
        if (_cache.TryGetValue(fileId, out var cache))
        {
            cache.ChunkCount = finalizeChunkCount;
            cache.PlainLength = newPlainLength;
        }
    }

    private static byte[] ResizeChunk(byte[] chunk, int newLen)
    {
        byte[] result = new byte[newLen];
        Array.Copy(chunk, result, Math.Min(chunk.Length, newLen));
        return result;
    }

    /// <summary>E2EE: 既存チャンクを DL + 復号して平文を返す（差分保存の RMW 用）。チャンクプールも更新。</summary>
    internal byte[] LoadPlainChunkForWrite(string fileId, int chunkIndex, byte[] fileKey, byte[] fileSalt)
    {
        var (data, revision) = _api.DownloadChunkAsync(_volumeName, fileId, chunkIndex).GetAwaiter().GetResult();
        byte[] chunk = E2eeCrypto.DecryptChunk(data, fileKey, chunkIndex, fileSalt, revision);
        PutChunkToPool(fileId, chunkIndex, chunk, ComputeHashHex(data));
        return chunk;
    }

    // ---- チャンクプール操作（グローバル20チャンク上限、ハッシュ検証付き） ----

    /// <summary>チャンクをグローバルプールから取得（LRU 昇格付き）。なければ null。</summary>
    internal (byte[] Data, string EncryptedHash)? TryGetChunkFromPool(string fileId, int chunkIndex)
    {
        lock (_chunkPoolLock)
        {
            var key = (fileId, chunkIndex);
            if (_chunkPool.TryGetValue(key, out var entry))
            {
                _chunkLru.Remove(key);
                _chunkLru.AddFirst(key);
                return entry;
            }
            return null;
        }
    }

    /// <summary>チャンクをグローバルプールに保存（LRU 退避付き）。</summary>
    internal void PutChunkToPool(string fileId, int chunkIndex, byte[] data, string encryptedHash)
    {
        lock (_chunkPoolLock)
        {
            var key = (fileId, chunkIndex);
            if (_chunkPool.ContainsKey(key))
            {
                _chunkLru.Remove(key);
                _chunkLru.AddFirst(key);
                _chunkPool[key] = (data, encryptedHash);
                return;
            }

            _chunkPool[key] = (data, encryptedHash);
            _chunkLru.AddFirst(key);

            while (_chunkPool.Count > MaxGlobalChunks)
            {
                var evict = _chunkLru.Last!.Value;
                _chunkLru.RemoveLast();
                _chunkPool.Remove(evict);
            }
        }
    }

    /// <summary>指定ファイルのチャンクを全てプールから除去。</summary>
    internal void RemoveFileChunksFromPool(string fileId)
    {
        lock (_chunkPoolLock)
        {
            var toRemove = _chunkPool.Keys.Where(k => k.FileId == fileId).ToList();
            foreach (var k in toRemove)
            {
                _chunkPool.Remove(k);
                _chunkLru.Remove(k);
            }
        }
    }

    private static string ComputeHashHex(byte[] data)
        => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(data));

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
                string decrypted = E2eeCrypto.DecryptFilename(entry.EncryptedName, _masterKey!.Buffer);
                _fileIdCache.TryAdd(decrypted, entry.FileId);
            }
            return _fileIdCache.TryGetValue(plainName, out var found) ? found : null;
        }
        catch { }

        return null;
    }

    /// <summary>アンマウント時: マスターキー（VirtualUnlock 含む）・ファイルキー・平文チャンクをゼロクリア。</summary>
    public void Dispose()
    {
        _masterKey?.Dispose();
        foreach (var cache in _cache.Values)
            cache.Dispose();
        _cache.Clear();

        // 平文チャンクプールもゼロクリア
        lock (_chunkPoolLock)
        {
            foreach (var (_, (data, _)) in _chunkPool)
                CryptographicOperations.ZeroMemory(data);
            _chunkPool.Clear();
            _chunkLru.Clear();
        }
    }

    private FileCache? GetOrCreateCache(string fileId)
    {
        // TryGetValue のみ使用 - 見つからなければ null を返す
        if (_cache.TryGetValue(fileId, out var c)) return c;

        // 見つからない場合のみ作成を試みる - API 失敗時は null を返す（キャッシュに保存しない）
        try
        {
            var entries = _api.ListFilesAsync(_volumeName).GetAwaiter().GetResult();
            var entry = entries.FirstOrDefault(e => e.FileId == fileId);
            if (entry is null) return null;

            string plainName = E2eeCrypto.DecryptFilename(entry.EncryptedName, _masterKey!.Buffer);
            long plainLength = Math.Max(0, entry.EncryptedLength - E2eeCrypto.SaltSize - (long)entry.ChunkCount * E2eeCrypto.GcmTagSize);
            var cache = new FileCache
            {
                PlainName = plainName,
                FileId = fileId,
                ChunkCount = entry.ChunkCount,
                PlainLength = plainLength,
            };
            _fileIdCache[plainName] = fileId;
            _cache.TryAdd(fileId, cache);
            return cache;
        }
        catch
        {
            return null;
        }
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
