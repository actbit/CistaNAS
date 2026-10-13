using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CistaNAS.Web.Services;

/// <summary>
/// アプリケーション更新の状態を読み取り、管理者の確認・承認をroot側のsystemdへ渡す。
/// アプリプロセス自身にはsystemctl実行権限を与えず、要求ファイルを介して更新する。
/// </summary>
public sealed class ApplicationUpdateService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly JsonSerializerOptions WriteJsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
    };
    private static readonly System.Text.RegularExpressions.Regex VersionPattern =
        new("^v[0-9]+\\.[0-9]+\\.[0-9]+$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private readonly string _statusPath;
    private readonly string _checkRequestPath;
    private readonly string _requestPath;
    private readonly object _requestGate = new();

    public ApplicationUpdateService(IConfiguration configuration)
    {
        _statusPath = configuration["CistaNas:Update:StatusPath"]
            ?? "/var/lib/cistanas/update-status.json";
        _checkRequestPath = configuration["CistaNas:Update:CheckRequestPath"]
            ?? "/var/lib/cistanas/update-check-request.json";
        _requestPath = configuration["CistaNas:Update:RequestPath"]
            ?? "/var/lib/cistanas/update-request.json";
    }

    public ApplicationUpdateStatus GetStatus()
    {
        try
        {
            if (File.Exists(_statusPath))
            {
                var json = File.ReadAllText(_statusPath);
                var status = JsonSerializer.Deserialize<ApplicationUpdateStatus>(json, JsonOptions);
                if (status is not null) return status;
            }
        }
        catch
        {
            // 更新処理中の一時的な読み取り失敗は、利用可能なローカル情報を返す。
        }

        return new ApplicationUpdateStatus(
            "not_checked",
            GetCurrentVersion(),
            null,
            false,
            null,
            null,
            "更新情報はまだ確認されていません。"
        );
    }

    public ApplicationUpdateStatus RequestCheck()
    {
        var directory = Path.GetDirectoryName(_checkRequestPath);
        if (string.IsNullOrWhiteSpace(directory))
            throw new ApplicationUpdateException("更新確認要求の保存先が不正です。");

        lock (_requestGate)
        {
            Directory.CreateDirectory(directory);
            var temporaryPath = $"{_checkRequestPath}.{Guid.NewGuid():N}.tmp";
            try
            {
                var request = JsonSerializer.Serialize(new CheckRequest(DateTimeOffset.UtcNow), WriteJsonOptions);
                File.WriteAllText(temporaryPath, request, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                File.Move(temporaryPath, _checkRequestPath, overwrite: true);
            }
            finally
            {
                try
                {
                    if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
                }
                catch
                {
                    // 主要処理のエラーを隠さない。
                }
            }
        }

        return GetStatus() with
        {
            State = "check_requested",
            Message = "更新確認を要求しました。"
        };
    }

    public ApplicationUpdateStatus RequestUpdate(string? requestedVersion)
    {
        var status = GetStatus();
        var version = string.IsNullOrWhiteSpace(requestedVersion)
            ? status.LatestVersion
            : requestedVersion.Trim();

        if (string.IsNullOrWhiteSpace(version) || !VersionPattern.IsMatch(version))
            throw new ApplicationUpdateException("更新対象のバージョンが不正です。");

        var directory = Path.GetDirectoryName(_requestPath);
        if (string.IsNullOrWhiteSpace(directory))
            throw new ApplicationUpdateException("更新要求の保存先が不正です。");

        lock (_requestGate)
        {
            Directory.CreateDirectory(directory);
            var temporaryPath = $"{_requestPath}.{Guid.NewGuid():N}.tmp";
            try
            {
                var request = JsonSerializer.Serialize(new UpdateRequest(version), WriteJsonOptions);
                File.WriteAllText(temporaryPath, request, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                File.Move(temporaryPath, _requestPath, overwrite: true);
            }
            finally
            {
                try
                {
                    if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
                }
                catch
                {
                    // 主要処理のエラーを隠さない。
                }
            }
        }

        return status with
        {
            State = "requested",
            RequestedVersion = version,
            Message = $"{version} の更新を要求しました。"
        };
    }

    private static string? GetCurrentVersion()
    {
        try
        {
            var link = new DirectoryInfo("/opt/cistanas/current");
            return link.ResolveLinkTarget(returnFinalTarget: true)?.Name;
        }
        catch
        {
            return null;
        }
    }

    private sealed record UpdateRequest(string Version);
    private sealed record CheckRequest(DateTimeOffset RequestedAt);
}

public sealed record ApplicationUpdateStatus(
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("currentVersion")] string? CurrentVersion,
    [property: JsonPropertyName("latestVersion")] string? LatestVersion,
    [property: JsonPropertyName("updateAvailable")] bool UpdateAvailable,
    [property: JsonPropertyName("requestedVersion")] string? RequestedVersion,
    [property: JsonPropertyName("checkedAt")] DateTimeOffset? CheckedAt,
    [property: JsonPropertyName("message")] string? Message
);

public sealed class ApplicationUpdateException(string message) : Exception(message);
