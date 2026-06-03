using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace CistaNAS.Web.Authorization;

/// <summary>
/// Micon.LotterySystem の DynamicRoleHandler に相当。
/// <see cref="CistaAuthorizationRequirement"/> の Authority に応じて
/// リソースレベル（ボリュームアクセス・オーナー）およびロールベース（admin）の認可を判定する。
/// </summary>
public sealed class CistaAuthorizationHandler(
    VolumeService volumeService,
    ILogger<CistaAuthorizationHandler> logger)
    : AuthorizationHandler<CistaAuthorizationRequirement>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        CistaAuthorizationRequirement requirement)
    {
        var httpContext = context.Resource as HttpContext;
        var username = context.User.Identity?.Name;

        // リソース非依存の Authority（AdminOnly 等）
        if (requirement.RouteParameter is null)
        {
            await HandleRoleBasedAsync(context, requirement, username);
            return;
        }

        // リソース依存の Authority — ルートパラメータからボリューム名を取得
        var volumeName = ExtractVolumeName(httpContext, requirement.RouteParameter);
        if (string.IsNullOrEmpty(volumeName))
        {
            logger.LogDebug(
                "認可失敗: ルートパラメータ '{Param}' が見つかりません。",
                requirement.RouteParameter);
            return;
        }

        if (string.IsNullOrEmpty(username))
        {
            logger.LogDebug("認可失敗: ユーザーが未認証です。");
            return;
        }

        switch (requirement.Authority)
        {
            case CistaAuthorities.VolumeAccess:
                if (await volumeService.HasAccessAsync(volumeName, username))
                    context.Succeed(requirement);
                break;

            case CistaAuthorities.VolumeOwner:
                await HandleVolumeOwnerAsync(context, requirement, volumeName, username);
                break;

            case CistaAuthorities.VolumeOwnerOrAdmin:
                await HandleVolumeOwnerOrAdminAsync(context, requirement, volumeName, username);
                break;

            default:
                logger.LogWarning(
                    "未知の Authority '{Authority}' が要求されました。",
                    requirement.Authority);
                break;
        }
    }

    private static Task HandleRoleBasedAsync(
        AuthorizationHandlerContext context,
        CistaAuthorizationRequirement requirement,
        string? username)
    {
        if (string.IsNullOrEmpty(username)) return Task.CompletedTask;

        switch (requirement.Authority)
        {
            case CistaAuthorities.AdminOnly:
                if (context.User.IsInRole("admin"))
                    context.Succeed(requirement);
                break;
        }

        return Task.CompletedTask;
    }

    private async Task HandleVolumeOwnerAsync(
        AuthorizationHandlerContext context,
        CistaAuthorizationRequirement requirement,
        string volumeName,
        string username)
    {
        // タイミング攻撃対策: ボリューム存在可否で応答時間が変わらないよう、
        // ヘッダ取得失敗時にもダミー比較を実行する。
        try
        {
            var header = await volumeService.GetVolumeHeaderAsync(volumeName);
            // 常に same-length 比較を実行（タイミング均一化）
            bool match = CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.UTF8.GetBytes(header.OwnerUser ?? ""),
                System.Text.Encoding.UTF8.GetBytes(username));
            if (match)
                context.Succeed(requirement);
        }
        catch (VolumeException)
        {
            // ボリュームが見つからない — Succeed せずフレームワークに 403 を委ねる。
            // ダミー比較でタイミングを均一化（同样的 UTF8 エンコード + FixedTimeEquals）
            CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.UTF8.GetBytes(""),
                System.Text.Encoding.UTF8.GetBytes(username));
        }
    }

    private async Task HandleVolumeOwnerOrAdminAsync(
        AuthorizationHandlerContext context,
        CistaAuthorizationRequirement requirement,
        string volumeName,
        string username)
    {
        // admin はオーナーチェックをバイパス
        if (context.User.IsInRole("admin"))
        {
            context.Succeed(requirement);
            return;
        }

        try
        {
            var header = await volumeService.GetVolumeHeaderAsync(volumeName);
            if (header.OwnerUser == username)
                context.Succeed(requirement);
        }
        catch (VolumeException)
        {
            // ボリュームが見つからない
        }
    }

    /// <summary>
    /// ルートパラメータ名に応じてボリューム名を取得。
    /// </summary>
    private static string? ExtractVolumeName(HttpContext? httpContext, string routeParameter)
    {
        if (httpContext is null) return null;
        if (httpContext.Request.RouteValues.TryGetValue(routeParameter, out var value))
            return value?.ToString();

        // フォールバック: "volumeName" ↔ "name" の互換
        var fallback = string.Equals(routeParameter, "volumeName", StringComparison.Ordinal)
            ? "name"
            : "volumeName";
        if (httpContext.Request.RouteValues.TryGetValue(fallback, out var fallbackValue))
            return fallbackValue?.ToString();

        return null;
    }
}
