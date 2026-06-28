using System.Collections.Concurrent;
using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// ボリュームの作成・マウント・ロック・共有を管理する Singleton Service。
/// メタデータは VolumeMetadataStore（IStorageProvider）経由で保存し、
/// volume.dat はローカルファイルシステムに配置。
/// 責務ごとに partial 分割（Lifecycle / Access / E2ee）。
/// </summary>
public sealed partial class VolumeService : IAsyncDisposable
{
    private int _disposed;
    private readonly IOptions<CistaNasOptions> _options;
    private readonly string _volumeDataPath;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly VolumeMetadataStore _metaStore;
    private readonly IChunkStore _chunkStore;
    private readonly ILogger<VolumeService> _logger;

    private readonly ConcurrentDictionary<string, MountedVolume> _mounted = new();
    private readonly SemaphoreSlim _mountGate = new(1, 1);

    private VolumeOptions VolOpts => _options.Value.Volume;
    private string StorageProvider => _options.Value.Storage.Provider.ToLowerInvariant();

    public VolumeService(
        IOptions<CistaNasOptions> options,
        IServiceScopeFactory scopeFactory,
        VolumeMetadataStore metaStore,
        IChunkStore chunkStore,
        ILogger<VolumeService> logger)
    {
        _options = options;
        _volumeDataPath = options.Value.Storage.VolumeDataPath ?? options.Value.DataRoot;
        _scopeFactory = scopeFactory;
        _metaStore = metaStore;
        _chunkStore = chunkStore;
        _logger = logger;
        Directory.CreateDirectory(_volumeDataPath);
    }

    /// <summary>"auto" 設定時に、S3 プロバイダ使用中ならチャンクモードにするかを判定。</summary>
    private bool ShouldUseChunkMode() =>
        VolOpts.ChunkStorage == "auto" && StorageProvider != "local";

    /// <summary>_mountGate の取得/解放をカプセル化し、try/finally の繰り返しを排除する。</summary>
    private async Task UnderMountGateAsync(Func<Task> action)
    {
        await _mountGate.WaitAsync();
        try { await action(); }
        finally { _mountGate.Release(); }
    }

    /// <summary>_mountGate の取得/解放をカプセル化（戻り値あり）。</summary>
    private async Task<T> UnderMountGateAsync<T>(Func<Task<T>> action)
    {
        await _mountGate.WaitAsync();
        try { return await action(); }
        finally { _mountGate.Release(); }
    }

    /// <summary>
    /// マウント済みボリュームの Stream と Header を I/O 用に取得。
    /// 返された <see cref="IDisposable"/> は I/O 完了後に必ず Dispose すること。
    /// LockAsync はアクティブな I/O ガードがすべて解放されるまで待機する。
    /// </summary>
    public async Task<(IDisposable IoGuard, Stream Stream, VolumeHeader Header)> GetMountedForIoAsync(string name, CancellationToken ct = default)
    {
        if (!_mounted.TryGetValue(name, out var mv))
            throw new VolumeException($"ボリューム '{name}' はマウントされていません。");
        var guard = await mv.IoTracker.EnterAsync(ct);
        return (guard, mv.Stream, mv.Header);
    }

    /// <summary>マウント済みボリュームの Header のみ取得（Stream 不要・I/O 追跡なし）。</summary>
    public (VolumeHeader Header, Stream Stream) GetMounted(string name)
    {
        if (!_mounted.TryGetValue(name, out var mv))
            throw new VolumeException($"ボリューム '{name}' はマウントされていません。");
        return (mv.Header, mv.Stream);
    }

    /// <summary>マウント済みボリュームの Header と MasterKey を取得（Stream は不要なケース用）。</summary>
    public (VolumeHeader Header, byte[]? MasterKey) GetMountedKeys(string name)
    {
        if (!_mounted.TryGetValue(name, out var mv))
            throw new VolumeException($"ボリューム '{name}' はマウントされていません。");
        return (mv.Header, mv.MasterKey);
    }

    /// <summary>ボリュームがチャンクストレージモードか。</summary>
    public bool IsChunkMode(string name)
    {
        var (header, _) = GetMountedKeys(name);
        return header.StorageMode == "chunk";
    }

    public bool IsMounted(string name) => _mounted.ContainsKey(name);

    // ---- マウント内部実装 ----

    private void MountInternal(string name, VolumeHeader header, byte[]? masterKey)
    {
        // E2EEはサーバー側で暗号化しないため、FileStream を排他保持しない
        var share = header.IsE2ee ? FileShare.ReadWrite : FileShare.None;
        var fs = new FileStream(GetDataPath(name), FileMode.Open, FileAccess.ReadWrite, share, 4096, FileOptions.Asynchronous);
        Stream stream = (header.Encrypted && masterKey is not null)
            ? new AesXtsStream(fs, masterKey, header.SectorSize, fs.Length, writable: true)
            : fs;
        _mounted[name] = new MountedVolume(header, masterKey, stream);
    }

    /// <summary>チャンクモード: FileStream を開かずにマウント。データは IChunkStore 経由でアクセス。</summary>
    private void MountInternalChunked(string name, VolumeHeader header, byte[]? masterKey)
    {
        // チャンクモードでは FileStream を持たない。ダミーの空ストリームを設定。
        // GetMounted() はチャンクモードでは呼ばれない前提（GetMountedKeys を使用）。
        _mounted[name] = new MountedVolume(header, masterKey, Stream.Null);
    }

    // ---- クラッシュ復旧 ----

    /// <summary>
    /// マウント直後に未コミットジャーナルがあればカタログを修復し、ジャーナルをクリアする。
    /// FileService（Scoped）をスコープ経由で取得する。復旧失敗はログに記録し、マウント自体は継続。
    /// </summary>
    private async Task RecoverMountedVolumeAsync(string name)
    {
        try
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var fileService = scope.ServiceProvider.GetRequiredService<FileService>();
            await fileService.RecoverAsync(name);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "ボリューム '{Volume}' のジャーナル復旧に失敗しました。", name);
        }
    }

    // ---- 内部ヘルパ ----

    private async Task<VolumeHeader> LoadHeaderOrThrowAsync(string name)
    {
        return (await _metaStore.LoadAsync(name))
            ?? throw new VolumeException($"ボリューム '{name}' が見つかりません。");
    }

    private async Task<VolumeHeader?> LoadHeaderIfExistsAsync(string name)
        => await _metaStore.LoadAsync(name);

    private void RefreshMountedHeader(string name, VolumeHeader updated)
    {
        if (_mounted.TryGetValue(name, out var mv))
            mv.UpdateHeader(updated);
    }

    private static VolumeInfo ToInfo(string name, VolumeHeader h, bool mounted)
    {
        var wrapTypes = h.UserKeys.Count > 0
            ? h.UserKeys.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.WrapType, StringComparer.Ordinal)
            : null;
        return new(name, mounted, h.Encrypted, h.OwnerUser, h.CreatedAt,
            h.UserKeys.Keys.ToList(), h.EncryptionMode,
            h.CipherAlgorithm, h.KeySize,
            h.AuthorizedGroups.ToList(),
            name.StartsWith(VolumeHeader.HomePrefix, StringComparison.Ordinal),
            wrapTypes);
    }

    private string VolumeDir(string name) => Path.Combine(_volumeDataPath, name);
    private string GetDataPath(string name) => Path.Combine(VolumeDir(name), "volume.dat");

    private static void ValidateName(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (name.StartsWith(VolumeHeader.HomePrefix, StringComparison.Ordinal))
            throw new VolumeException("'home__' で始まる名前は予約されています。");
        if (name.StartsWith(VolumeHeader.GroupPrefix, StringComparison.Ordinal))
            throw new VolumeException("'group__' で始まる名前は予約されています。グループボリュームは別途作成してください。");
        if (name.Length > 64)
            throw new VolumeException("ボリューム名は 64 文字以内にしてください。");
        foreach (char c in name)
        {
            if (!char.IsLetterOrDigit(c) && c != '-' && c != '_' && c != '.')
                throw new VolumeException("ボリューム名に使用できない文字が含まれています。");
        }
        if (name == "." || name == "..")
            throw new VolumeException("ボリューム名に使用できない文字が含まれています。");
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;

        // すべてのマウント済みボリュームの I/O 完了を待機
        var tasks = new List<Task>(_mounted.Count);
        foreach (var kvp in _mounted)
        {
            var mv = kvp.Value;
            tasks.Add(Task.Run(async () =>
            {
                await mv.IoTracker.WaitForZeroAsync();
                mv.Stream.Dispose();
                if (mv.MasterKey is not null)
                    CryptographicOperations.ZeroMemory(mv.MasterKey);
            }));
        }
        await Task.WhenAll(tasks);

        _mounted.Clear();
        _mountGate.Dispose();
    }

    private sealed class MountedVolume(VolumeHeader header, byte[]? masterKey, Stream stream)
    {
        private volatile VolumeHeader _header = header;
        public VolumeHeader Header { get => _header; private set => _header = value; }
        public byte[]? MasterKey { get; } = masterKey;
        public Stream Stream { get; } = stream;
        public ActiveIoTracker IoTracker { get; } = new();
        public void UpdateHeader(VolumeHeader h) => Header = h;
    }

    /// <summary>
    /// マウント済みボリュームのアクティブ I/O 数を追跡し、
    /// <see cref="LockAsync"/> がすべての I/O 完了を待機できるようにする。
    /// </summary>
    private sealed class ActiveIoTracker
    {
        private int _activeCount;
        private readonly object _gate = new();
        private TaskCompletionSource<object?>? _zeroTcs;

        public Task<IDisposable> EnterAsync(CancellationToken ct)
        {
            // 同期ロックで _activeCount をインクリメント
            // （非同期ロールバックの心配はないため lock で十分）
            lock (_gate)
            {
                _activeCount++;
            }
            return Task.FromResult<IDisposable>(new Releaser(this));
        }

        /// <summary>アクティブ I/O がゼロになるまで待機する。</summary>
        public async Task WaitForZeroAsync()
        {
            TaskCompletionSource<object?>? tcs;
            lock (_gate)
            {
                if (_activeCount == 0)
                    return;
                // 既存の TCS があれば再利用し、なければ新規作成
                tcs = _zeroTcs;
                if (tcs is null)
                {
                    tcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
                    _zeroTcs = tcs;
                }
            }
            await tcs.Task;
        }

        private void Exit()
        {
            // lock 内で _activeCount をデクリメントし、ゼロになったら _zeroTcs を完了
            bool shouldSignal;
            lock (_gate)
            {
                _activeCount--;
                shouldSignal = _activeCount == 0;
                if (shouldSignal)
                    _zeroTcs?.TrySetResult(null);
            }
        }

        private sealed class Releaser(ActiveIoTracker tracker) : IDisposable
        {
            public void Dispose() => tracker.Exit();
        }
    }
}
