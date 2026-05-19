namespace CistaNAS.Web.Models;

/// <summary>ログイン要求（/api/v1/auth/login・Blazor ログイン共通）。</summary>
public sealed record LoginRequest(string Username, string Password);

/// <summary>初期セットアップ要求（/api/v1/auth/setup）。</summary>
public sealed record SetupRequest(string Username, string Password);

/// <summary>ログイン成功時に返す JWT。</summary>
public sealed record LoginResponse(string AccessToken, string TokenType, DateTimeOffset ExpiresAt);

/// <summary>users.json に永続化するユーザアカウント。</summary>
public sealed class UserAccount
{
    public required string Username { get; set; }
    public required string PasswordHash { get; set; }
    public string Role { get; set; } = "admin";

    /// <summary>Base64(raw 65B) エンコードされた ECDH P-256 公開鍵。null は未生成。</summary>
    public string? PublicKey { get; set; }
}
