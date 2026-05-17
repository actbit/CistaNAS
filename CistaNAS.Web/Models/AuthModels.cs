namespace CistaNAS.Web.Models;

/// <summary>ログイン要求（/api/v1/auth/login・Blazor ログイン共通）。</summary>
public sealed record LoginRequest(string Username, string Password);

/// <summary>ログイン成功時に返す JWT。</summary>
public sealed record LoginResponse(string AccessToken, string TokenType, DateTimeOffset ExpiresAt);

/// <summary>users.json に永続化するユーザアカウント。</summary>
public sealed class UserAccount
{
    public required string Username { get; set; }
    public required string PasswordHash { get; set; }
    public string Role { get; set; } = "admin";
}
