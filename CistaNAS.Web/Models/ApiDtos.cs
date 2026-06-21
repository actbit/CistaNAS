namespace CistaNAS.Web.Models;

/// <summary>グループ一覧 API 用 DTO（EF ナビゲーションの循環参照回避・過剰シリアライズ防止）。</summary>
public sealed record GroupDto(
    string GroupName,
    string OwnerUser,
    DateTimeOffset CreatedAt,
    IReadOnlyList<MemberDto> Members);

public sealed record MemberDto(string Username);

/// <summary>ユーザー一覧 API 用 DTO。</summary>
public sealed record UserDto(
    string UserName,
    IList<string> Roles);
