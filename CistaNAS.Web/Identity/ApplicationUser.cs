using Microsoft.AspNetCore.Identity;

namespace CistaNAS.Web.Identity;

public sealed class ApplicationUser : IdentityUser<string>
{
    public ApplicationUser() { Id = Guid.NewGuid().ToString(); }

    /// <summary>Base64(raw 65B) encoded ECDH P-256 public key. null = not generated.</summary>
    public string? PublicKey { get; set; }

    /// <summary>デフォルトの暗号化モード ("server" または "e2ee")</summary>
    public string DefaultEncryptionMode { get; set; } = "server";

    /// <summary>デフォルトの暗号化アルゴリズム ("aes-256-xts", "aes-256-gcm", "chacha20-poly1305")</summary>
    public string DefaultCipherAlgorithm { get; set; } = "aes-256-xts";
}
