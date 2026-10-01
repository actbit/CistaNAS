using System.Collections.Concurrent;
using CistaNAS.Wasm.Auth;

namespace CistaNAS.Wasm.Services;

/// <summary>
/// ブラウザ WASM メモリ上のボリュームマウント状態管理。
/// サーバー側 VolumeService の Singleton 相当。
/// 各タブで独立（WASM の DI Singleton は同一タブ内で共有）。
/// </summary>
public sealed class ClientVolumeMountService : IDisposable
{
    private readonly WasmAuthStateProvider _auth;
    private readonly E2eeInterop _crypto;
    private bool _disposed;

    public ClientVolumeMountService(WasmAuthStateProvider auth, E2eeInterop crypto)
    {
        _auth = auth; _crypto = crypto;
        _auth.SessionInvalidated += ClearMounts;
    }

    public long CaptureSession()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_auth.IsLoggedIn) throw new OperationCanceledException("ログイン状態が終了しました。");
        return _auth.AuthenticationVersion;
    }

    public void EnsureCurrentSession(long version)
    {
        if (CaptureSession() != version) throw new OperationCanceledException("認証状態が変更されました。");
    }
    /// <summary>マウント済みボリュームの情報。</summary>
    private sealed class MountedVolume
    {
        public string VolumeName { get; init; } = "";
        public string EncryptionMode { get; init; } = "server";
        public string CipherAlgorithm { get; init; } = "aes-256-xts";
        public int SectorSize { get; init; }
        public int ChunkSize { get; init; }
        /// <summary>サーバー暗号化ボリュームのマスターキー (64 bytes for AES-XTS)。</summary>
        public byte[]? MasterKey { get; set; }
        /// <summary>E2EE マスターキーの JS interop ハンドル。</summary>
        public string? E2eeMasterKeyHandle { get; set; }
        /// <summary>共有 v2: epoch → GroupKey (base64)。KeyEpoch ≥ 1 のファイル/ファイル名の復号に使う。旧 epoch も保持（旧ファイル読取用）。</summary>
        public Dictionary<int, string> GroupKeysByEpoch { get; init; } = new();
        /// <summary>共有 v2: ボリュームヘッダの VolumeId（AAD bind 用）。v2 未移行では null。</summary>
        public string? VolumeId { get; init; }
    }

    private readonly ConcurrentDictionary<string, MountedVolume> _mounted = new(StringComparer.Ordinal);

    /// <summary>ボリュームがマウント済みか。</summary>
    public bool IsMounted(string volumeName) => CanReadMounts() && _mounted.ContainsKey(volumeName);

    /// <summary>マウント済みボリューム一覧。</summary>
    public IReadOnlyList<string> MountedVolumes => CanReadMounts() ? _mounted.Keys.ToList() : [];

    /// <summary>サーバー暗号化ボリュームをマウント（キーを保持）。</summary>
    public void MountServerEncrypted(string volumeName, byte[] masterKey, string cipherAlgorithm, int sectorSize, int chunkSize,
        long? sessionVersion = null)
    {
        Replace(volumeName, new MountedVolume
        {
            VolumeName = volumeName,
            EncryptionMode = "server",
            CipherAlgorithm = cipherAlgorithm,
            SectorSize = sectorSize,
            ChunkSize = chunkSize,
            MasterKey = masterKey,
        }, sessionVersion);
    }

    /// <summary>E2EE ボリュームをマウント（JS interop キーハンドルを保持）。</summary>
    public void MountE2ee(string volumeName, string masterKeyHandle, int chunkSize, string encryptionMode, long? sessionVersion = null)
    {
        Replace(volumeName, new MountedVolume
        {
            VolumeName = volumeName,
            EncryptionMode = encryptionMode,
            ChunkSize = chunkSize,
            E2eeMasterKeyHandle = masterKeyHandle,
        }, sessionVersion);
    }

    /// <summary>
    /// E2EE ボリュームをマウント（共有 v2: GroupKey 辞書 + VolumeId を保持）。
    /// masterKeyHandle は v1 ファイルの読み取り用（masterKey を持たない v2 メンバーでは null）。
    /// </summary>
    public void MountE2ee(string volumeName, string? masterKeyHandle, int chunkSize, string encryptionMode,
        string? volumeId, IReadOnlyDictionary<int, string> groupKeysByEpoch, long? sessionVersion = null)
    {
        Replace(volumeName, new MountedVolume
        {
            VolumeName = volumeName,
            EncryptionMode = encryptionMode,
            ChunkSize = chunkSize,
            E2eeMasterKeyHandle = masterKeyHandle,
            VolumeId = volumeId,
            GroupKeysByEpoch = new Dictionary<int, string>(groupKeysByEpoch),
        }, sessionVersion);
    }

    /// <summary>共有 v2: ボリュームの GroupKey 辞書（epoch → base64）と VolumeId を取得。未マウント時は null。</summary>
    public (string? VolumeId, IReadOnlyDictionary<int, string> GroupKeys)? GetE2eeV2Keys(string volumeName)
    {
        if (!CanReadMounts() || !_mounted.TryGetValue(volumeName, out var mv)) return null;
        return (mv.VolumeId, mv.GroupKeysByEpoch);
    }

    /// <summary>ボリュームをロック（アンマウント）。</summary>
    public void Lock(string volumeName)
    {
        if (_mounted.TryRemove(volumeName, out var mv))
        {
            Release(mv);
        }
    }

    /// <summary>マウント済みボリュームのマスターキーを取得（サーバー暗号化）。</summary>
    public byte[]? GetMasterKey(string volumeName)
        => CanReadMounts() && _mounted.TryGetValue(volumeName, out var mv) ? mv.MasterKey : null;

    /// <summary>マウント済みボリュームの E2EE キーハンドルを取得。</summary>
    public string? GetE2eeKeyHandle(string volumeName)
        => CanReadMounts() && _mounted.TryGetValue(volumeName, out var mv) ? mv.E2eeMasterKeyHandle : null;

    /// <summary>マウント済みボリュームの情報を取得。</summary>
    public (string EncryptionMode, string CipherAlgorithm, int SectorSize, int ChunkSize) GetVolumeInfo(string volumeName)
    {
        if (!CanReadMounts() || !_mounted.TryGetValue(volumeName, out var mv))
            throw new InvalidOperationException($"ボリューム '{volumeName}' はマウントされていません。");
        return (mv.EncryptionMode, mv.CipherAlgorithm, mv.SectorSize, mv.ChunkSize);
    }

    /// <summary>マウント済みかどうかと E2EE かどうかを取得。</summary>
    public (bool mounted, bool isE2ee) GetMountStatus(string volumeName)
    {
        if (!CanReadMounts() || !_mounted.TryGetValue(volumeName, out var mv)) return (false, false);
        return (true, mv.EncryptionMode is "e2ee" or "group-e2ee");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _auth.SessionInvalidated -= ClearMounts;
        ClearMounts();
    }

    private bool CanReadMounts()
    {
        if (!_disposed && _auth.IsLoggedIn) return true;
        ClearMounts();
        return false;
    }

    private void Replace(string name, MountedVolume next, long? version)
    {
        EnsureCurrentSession(version ?? CaptureSession());
        _mounted.TryGetValue(name, out var previous);
        _mounted[name] = next;
        if (previous is not null) Release(previous, next);
    }

    private void ClearMounts()
    {
        foreach (string name in _mounted.Keys)
            if (_mounted.TryRemove(name, out var previous)) Release(previous);
    }

    private void Release(MountedVolume previous, MountedVolume? retained = null)
    {
        if (previous.MasterKey is not null && !ReferenceEquals(previous.MasterKey, retained?.MasterKey))
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(previous.MasterKey);
        previous.MasterKey = null;
        previous.GroupKeysByEpoch.Clear();
        if (previous.E2eeMasterKeyHandle is { } handle && handle != retained?.E2eeMasterKeyHandle)
            _ = ClearHandleAsync(handle);
        previous.E2eeMasterKeyHandle = null;
    }

    private async Task ClearHandleAsync(string handle)
    {
        try { await _crypto.ClearKey(handle); }
        catch { /* ブラウザ終了時は JS ランタイム自体が破棄済みの場合がある。 */ }
    }
}
