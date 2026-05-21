using Microsoft.AspNetCore.Identity;

namespace CistaNAS.Web.Identity;

public sealed class ApplicationUser : IdentityUser<string>
{
    public ApplicationUser() { Id = Guid.NewGuid().ToString(); }

    /// <summary>Base64(raw 65B) encoded ECDH P-256 public key. null = not generated.</summary>
    public string? PublicKey { get; set; }
}
