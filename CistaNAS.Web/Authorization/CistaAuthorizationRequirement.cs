using Microsoft.AspNetCore.Authorization;

namespace CistaNAS.Web.Authorization;

/// <summary>
/// CistaNAS の認可要求。
/// <see cref="CistaAuthorities"/> に定義された Authority 名を保持し、
/// <see cref="CistaAuthorizationHandler"/> がルートパラメータとともに判定する。
/// </summary>
/// <param name="authority"><see cref="CistaAuthorities"/> の定数値。</param>
/// <param name="routeParameter">
/// ボリューム名を格納するルートパラメータ名。
/// "volumeName"（files / e2ee グループ）または "name"（volumes グループ）。
/// リソース依存しない Authority の場合は null。
/// </param>
public sealed class CistaAuthorizationRequirement(
    string authority,
    string? routeParameter = null) : IAuthorizationRequirement
{
    public string Authority { get; } = authority;

    /// <summary>
    /// ボリューム名を含むルートパラメータ名（"volumeName" または "name"）。
    /// リソース非依存の Authority（AdminOnly 等）では null。
    /// </summary>
    public string? RouteParameter { get; } = routeParameter;
}
