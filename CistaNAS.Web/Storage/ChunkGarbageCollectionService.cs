using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Storage;

/// <summary>
/// 保留期間を経過した孤児チャンクを定期的に回収するバックグラウンドサービス。
/// 起動処理とは分離し、削除失敗は次回周期へ持ち越す。
/// </summary>
public sealed class ChunkGarbageCollectionService : BackgroundService
{
    private readonly VolumeService _volumeService;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly TimeSpan _interval;
    private readonly bool _enabled;
    private readonly ILogger<ChunkGarbageCollectionService> _logger;

    public ChunkGarbageCollectionService(
        VolumeService volumeService,
        IServiceScopeFactory scopeFactory,
        IOptions<CistaNasOptions> options,
        ILogger<ChunkGarbageCollectionService> logger)
    {
        _volumeService = volumeService;
        _scopeFactory = scopeFactory;
        _interval = TimeSpan.FromMinutes(options.Value.Volume.ChunkGcIntervalMinutes);
        _enabled = options.Value.Volume.ChunkGcEnabled;
        _logger = logger;
    }

    /// <summary>テストまたは運用用の1回分のGCを実行する。</summary>
    public async Task RunOnceAsync(CancellationToken ct = default)
    {
        if (!_enabled) return;

        await using var scope = _scopeFactory.CreateAsyncScope();
        var collector = scope.ServiceProvider.GetRequiredService<ChunkGarbageCollector>();
        // GCは暗号鍵を必要としないため、マウント済みVolumeに限定しない。
        // サーバー再起動後や、パスワードが未入力で未マウントのVolumeも対象にする。
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
            _logger.LogWarning(ex, "孤児チャンクGCのボリューム一覧を取得できません。次回周期に再試行します。");
            return;
        }
        foreach (string volumeName in volumeNames)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                ChunkGcReport report = await collector.CollectAsync(volumeName, dryRun: false, ct);
                if (report.DeletedCount > 0 || report.Failed.Count > 0)
                {
                    _logger.LogInformation(
                        "ボリューム '{Volume}' の自動GCを実行しました。削除: {Deleted}, 失敗: {Failed}",
                        volumeName, report.DeletedCount, report.Failed.Count);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // 一時的なストレージ障害では候補を削除せず、次回周期で再試行する。
                _logger.LogWarning(ex, "ボリューム '{Volume}' の自動GCを延期しました。", volumeName);
            }
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_enabled) return;

        try
        {
            // ホスト起動とGCの一覧・削除処理を分離する。
            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
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
}
