using System.Collections.Concurrent;
using System.Text.Json;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// 保存済みチャンクボリュームの整合性を、起動処理とは分離して段階的に監査する。
/// 1回の実行で全ファイルを読み切らず、ボリュームごとのカーソルで次回へ継続する。
/// </summary>
public sealed class VolumeIntegrityAuditService : BackgroundService
{
    private readonly VolumeService _volumeService;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly TimeSpan _interval;
    private readonly int _batchSize;
    private readonly ILogger<VolumeIntegrityAuditService> _logger;
    private readonly ConcurrentDictionary<string, int> _cursors = new(StringComparer.Ordinal);
    private readonly string _statePath;
    private readonly SemaphoreSlim _runGate = new(1, 1);

    public VolumeIntegrityAuditService(
        VolumeService volumeService,
        IServiceScopeFactory scopeFactory,
        IOptions<CistaNasOptions> options,
        ILogger<VolumeIntegrityAuditService> logger)
    {
        _volumeService = volumeService;
        _scopeFactory = scopeFactory;
        _interval = TimeSpan.FromMinutes(options.Value.Volume.IntegrityAuditIntervalMinutes);
        _batchSize = options.Value.Volume.IntegrityAuditBatchSize;
        _logger = logger;
        _statePath = Path.Combine(
            Path.GetFullPath(options.Value.DataRoot), ".cistanas-integrity-audit.json");
        LoadState();
    }

    /// <summary>テストまたは管理用の1回分の監査を実行する。</summary>
    public async Task RunOnceAsync(CancellationToken ct = default)
    {
        await _runGate.WaitAsync(ct);
        try
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var fileService = scope.ServiceProvider.GetRequiredService<FileService>();
            var e2eeFileService = scope.ServiceProvider.GetRequiredService<E2eeFileService>();

            // E2EEチャンクVolumeは暗号文ハッシュだけで監査できるため、未マウントでも対象にする。
            // サーバー暗号化Volumeは復号鍵が必要なので、従来どおりマウント済みだけを対象にする。
            IReadOnlyList<string> volumeNames;
            try
            {
                volumeNames = await _volumeService.ListStoredVolumeNamesAsync(ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "整合性監査のボリューム一覧を取得できません。次回周期に再試行します。");
                return;
            }
            foreach (string volumeName in volumeNames)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    await AuditVolumeAsync(volumeName, fileService, e2eeFileService, ct);
                    await SaveStateAsync(ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    // 一時的なストレージ障害でサービス全体を停止させず、次回周期で再試行する。
                    _logger.LogWarning(ex, "ボリューム '{Volume}' のバックグラウンド整合性監査を延期しました。", volumeName);
                }
            }
        }
        finally
        {
            _runGate.Release();
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            // ホスト起動完了を優先し、監査は別の非同期処理として開始する。
            await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
            using var timer = new PeriodicTimer(_interval);
            await RunOnceAsync(stoppingToken);
            while (await timer.WaitForNextTickAsync(stoppingToken))
                await RunOnceAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // 正常停止。
        }
    }

    private async Task AuditVolumeAsync(
        string volumeName,
        FileService fileService,
        E2eeFileService e2eeFileService,
        CancellationToken ct)
    {
        var header = await _volumeService.GetStoredHeaderAsync(volumeName, ct);
        if (!string.Equals(header.StorageMode, "chunk", StringComparison.Ordinal))
            return;

        if (header.IsE2ee)
        {
            IReadOnlyList<string> fileIds = _volumeService.IsMounted(volumeName)
                ? (await e2eeFileService.ListFilesAsync(volumeName, ct)).Files
                    .Select(file => file.FileId)
                    .OrderBy(id => id, StringComparer.Ordinal)
                    .ToArray()
                : await e2eeFileService.ListStoredFileIdsAsync(volumeName, ct);
            Func<string, Task<FileIntegrityReport>> verify = _volumeService.IsMounted(volumeName)
                ? id => e2eeFileService.VerifyIntegrityAsync(volumeName, id, ct)
                : id => e2eeFileService.VerifyStoredIntegrityAsync(volumeName, id, ct);
            await AuditBatchAsync(volumeName, fileIds,
                verify, ct);
        }
        else
        {
            // サーバー暗号化チャンクは認証タグの検証にMasterKeyが必要。
            if (!_volumeService.IsMounted(volumeName))
                return;
            var fileNames = (await fileService.ListAsync(volumeName, ct)).Files
                .Select(file => file.Name)
                .OrderBy(name => name, StringComparer.Ordinal)
                .ToArray();
            await AuditBatchAsync(volumeName, fileNames,
                name => fileService.VerifyIntegrityAsync(volumeName, name, ct), ct);
        }
    }

    private async Task AuditBatchAsync(
        string volumeName,
        IReadOnlyList<string> fileIds,
        Func<string, Task<FileIntegrityReport>> verify,
        CancellationToken ct)
    {
        if (fileIds.Count == 0)
        {
            _cursors.TryRemove(volumeName, out _);
            return;
        }

        int start = _cursors.TryGetValue(volumeName, out int cursor) ? cursor : 0;
        if (start >= fileIds.Count) start = 0;
        int count = Math.Min(_batchSize, fileIds.Count);
        for (int offset = 0; offset < count; offset++)
        {
            ct.ThrowIfCancellationRequested();
            string fileId = fileIds[(start + offset) % fileIds.Count];
            FileIntegrityReport report = await verify(fileId);
            if (!report.IsHealthy)
            {
                _logger.LogWarning(
                    "ボリューム '{Volume}' のファイル '{File}' に整合性異常を検出しました。NeedsRepair=true を維持します。",
                    volumeName, fileId);
            }
        }

        _cursors[volumeName] = (start + count) % fileIds.Count;
    }

    private void LoadState()
    {
        try
        {
            if (!File.Exists(_statePath)) return;
            string json = File.ReadAllText(_statePath);
            var state = JsonSerializer.Deserialize<Dictionary<string, int>>(json);
            if (state is null) return;
            foreach (var pair in state)
            {
                if (pair.Value >= 0)
                    _cursors[pair.Key] = pair.Value;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "整合性監査の進捗を読み込めません。先頭から再開します。");
        }
    }

    private async Task SaveStateAsync(CancellationToken ct)
    {
        try
        {
            string? directory = Path.GetDirectoryName(_statePath);
            if (directory is not null) Directory.CreateDirectory(directory);
            string temporary = _statePath + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                var snapshot = _cursors.ToDictionary(pair => pair.Key, pair => pair.Value,
                    StringComparer.Ordinal);
                await using (var stream = new FileStream(
                    temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                    4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    await JsonSerializer.SerializeAsync(stream, snapshot, cancellationToken: ct);
                    await stream.FlushAsync(ct);
                    stream.Flush(flushToDisk: true);
                }
                File.Move(temporary, _statePath, overwrite: true);
            }
            finally
            {
                try { File.Delete(temporary); } catch { /* best effort */ }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // 監査結果を失敗扱いにせず、次回は保存済みカーソルから再開する。
            _logger.LogWarning(ex, "整合性監査の進捗を保存できません。次回は直前の進捗から再開します。");
        }
    }
}
