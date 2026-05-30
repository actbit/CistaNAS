using System.Collections.Concurrent;
using CistaNAS.Web.Configuration;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// メディアストリーミング用の短命トークンを管理。
/// ブラウザの video/audio/img は Authorization ヘッダーを送れないため、
/// クエリパラメータで一時的なアクセス権を付与する。
/// Range 要求（動画シーク）に対応するため、トークンは有効期限内で再利用可能。
/// </summary>
public sealed class StreamingTokenService : BackgroundService
{
    private readonly ConcurrentDictionary<string, StreamingToken> _tokens = new();
    private readonly TimeSpan _ttl;
    private readonly TimeSpan _cleanupInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(5);

    public StreamingTokenService(IOptions<CistaNasOptions> options)
    {
        _ttl = TimeSpan.FromSeconds(options.Value.StreamingTokenTtlSeconds);
    }

    public string Issue(string username, string volumeName, string fileName)
    {
        // グローバルトークン数の上限チェック（バックグラウンド Cleanup が期限切れを削除）
        if (_tokens.Count >= 10000)
            throw new InvalidOperationException("ストリーミングトークンの発行数が制限を超えました。");
        string token = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        _tokens[token] = new StreamingToken(username, volumeName, fileName, DateTimeOffset.UtcNow + _ttl);
        return token;
    }

    /// <summary>
    /// トークンを検証。有効期限内であれば複数回呼び出し可能（Range 要求対応）。
    /// </summary>
    public (string Username, string VolumeName, string FileName)? Validate(string token)
    {
        if (!_tokens.TryGetValue(token, out var t)) return null;
        if (t.ExpiresAt + ClockSkew < DateTimeOffset.UtcNow)
        {
            _tokens.TryRemove(token, out _);
            return null;
        }
        return (t.Username, t.VolumeName, t.FileName);
    }

    /// <summary>期限切れトークンを定期的に削除するバックグラウンド処理。</summary>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(_cleanupInterval, stoppingToken);
            Cleanup();
        }
    }

    private void Cleanup()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kvp in _tokens)
        {
            if (kvp.Value.ExpiresAt + ClockSkew < now)
                _tokens.TryRemove(kvp.Key, out _);
        }
    }

    private sealed record StreamingToken(string Username, string VolumeName, string FileName, DateTimeOffset ExpiresAt);
}
