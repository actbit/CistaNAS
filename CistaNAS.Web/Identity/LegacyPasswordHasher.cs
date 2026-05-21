using System.Security.Cryptography;
using CistaNAS.Web.Crypto;
using Microsoft.AspNetCore.Identity;

namespace CistaNAS.Web.Identity;

/// <summary>
/// Supports legacy CistaNAS PBKDF2-SHA256 hashes (format: pbkdf2-sha256$iterations$salt$hash)
/// while delegating new hashes to the built-in Identity V3 hasher.
/// </summary>
public sealed class LegacyPasswordHasher : IPasswordHasher<ApplicationUser>
{
    private const string LegacyPrefix = "pbkdf2-sha256";

    private readonly PasswordHasher<ApplicationUser> _newHasher = new();

    public string HashPassword(ApplicationUser user, string password)
        => _newHasher.HashPassword(user, password);

    public PasswordVerificationResult VerifyHashedPassword(
        ApplicationUser user, string hashedPassword, string providedPassword)
    {
        if (string.IsNullOrEmpty(hashedPassword) || string.IsNullOrEmpty(providedPassword))
            return PasswordVerificationResult.Failed;

        if (hashedPassword.StartsWith(LegacyPrefix + "$", StringComparison.Ordinal))
        {
            bool valid = PasswordHasher.Verify(providedPassword, hashedPassword);
            return valid
                ? PasswordVerificationResult.SuccessRehashNeeded
                : PasswordVerificationResult.Failed;
        }

        return _newHasher.VerifyHashedPassword(user, hashedPassword, providedPassword);
    }
}
