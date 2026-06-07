using System.Collections.Concurrent;

namespace CistaNAS.Wasm.Services;

/// <summary>
/// ブラウザ WASM メモリ上のボリュームマウント状態管理。
/// サーバー側 VolumeService の Singleton 相当。
/// 各タブで独立（WASM の DI Singleton は同一タブ内で共有）。
/// </summary>
public sealed class ClientVolumeMountService : IDisposable
{
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
    }

    private readonly ConcurrentDictionary<string, MountedVolume> _mounted = new(StringComparer.Ordinal);

    /// <summary>ボリュームがマウント済みか。</summary>
    public bool IsMounted(string volumeName) => _mounted.ContainsKey(volumeName);

    /// <summary>マウント済みボリューム一覧。</summary>
    public IReadOnlyList<string> MountedVolumes => _mounted.Keys.ToList();

    /// <summary>サーバー暗号化ボリュームをマウント（キーを保持）。</summary>
    public void MountServerEncrypted(string volumeName, byte[] masterKey, string cipherAlgorithm, int sectorSize, int chunkSize)
    {
        _mounted[volumeName] = new MountedVolume
        {
            VolumeName = volumeName,
            EncryptionMode = "server",
            CipherAlgorithm = cipherAlgorithm,
            SectorSize = sectorSize,
            ChunkSize = chunkSize,
            MasterKey = masterKey,
        };
    }

    /// <summary>E2EE ボリュームをマウント（JS interop キーハンドルを保持）。</summary>
    public void MountE2ee(string volumeName, string masterKeyHandle, int chunkSize, string encryptionMode)
    {
        _mounted[volumeName] = new MountedVolume
        {
            VolumeName = volumeName,
            EncryptionMode = encryptionMode,
            ChunkSize = chunkSize,
            E2eeMasterKeyHandle = masterKeyHandle,
        };
    }

    /// <summary>ボリュームをロック（アンマウント）。</summary>
    public void Lock(string volumeName)
    {
        if (_mounted.TryRemove(volumeName, out var mv))
        {
            if (mv.MasterKey is not null)
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(mv.MasterKey);
            // E2EE キーハンドルは JS 側でクリアする必要があるため呼び出し元で処理
        }
    }

    /// <summary>マウント済みボリュームのマスターキーを取得（サーバー暗号化）。</summary>
    public byte[]? GetMasterKey(string volumeName)
        => _mounted.TryGetValue(volumeName, out var mv) ? mv.MasterKey : null;

    /// <summary>マウント済みボリュームの E2EE キーハンドルを取得。</summary>
    public string? GetE2eeKeyHandle(string volumeName)
        => _mounted.TryGetValue(volumeName, out var mv) ? mv.E2eeMasterKeyHandle : null;

    /// <summary>マウント済みボリュームの情報を取得。</summary>
    public (string EncryptionMode, string CipherAlgorithm, int SectorSize, int ChunkSize) GetVolumeInfo(string volumeName)
    {
        if (!_mounted.TryGetValue(volumeName, out var mv))
            throw new InvalidOperationException($"ボリューム '{volumeName}' はマウントされていません。");
        return (mv.EncryptionMode, mv.CipherAlgorithm, mv.SectorSize, mv.ChunkSize);
    }

    /// <summary>マウント済みかどうかと E2EE かどうかを取得。</summary>
    public (bool mounted, bool isE2ee) GetMountStatus(string volumeName)
    {
        if (!_mounted.TryGetValue(volumeName, out var mv)) return (false, false);
        return (true, mv.EncryptionMode is "e2ee" or "group-e2ee");
    }

    public void Dispose()
    {
        foreach (var kvp in _mounted)
        {
            if (kvp.Value.MasterKey is not null)
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(kvp.Value.MasterKey);
        }
        _mounted.Clear();
    }
}
