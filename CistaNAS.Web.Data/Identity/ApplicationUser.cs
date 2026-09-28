using Microsoft.AspNetCore.Identity;

namespace CistaNAS.Web.Identity;

public sealed class ApplicationUser : IdentityUser<string>
{
    public ApplicationUser() { Id = Guid.NewGuid().ToString(); }

    /// <summary>Base64(raw 65B) encoded ECDH P-256 public key. null = not generated.</summary>
    public string? PublicKey { get; set; }

    /// <summary>ECDH identity 導出用 salt（非秘密、CSPRNG 32B）。null = 未セットアップ。</summary>
    public byte[]? EcdhIdentitySalt { get; set; }

    /// <summary>ECDH identity 導出バージョン（EcdhIdentityKey.CurrentDerivationVersion）。</summary>
    public int EcdhDerivationVersion { get; set; }

    /// <summary>このユーザーが共有機能（E2EE 共有・招待・グループ共有）を利用可能か。
    /// 既存ユーザーは互換性のため既定 true。false でも private E2EE は利用可能。既存共有は自動 revoke されない。</summary>
    public bool SharingEnabled { get; set; } = true;

    /// <summary>デフォルトの暗号化モード ("server" または "e2ee")</summary>
    public string DefaultEncryptionMode { get; set; } = "server";

    /// <summary>デフォルトの暗号化アルゴリズム ("aes-256-xts", "aes-256-gcm", "chacha20-poly1305")</summary>
    public string DefaultCipherAlgorithm { get; set; } = "aes-256-xts";
}
