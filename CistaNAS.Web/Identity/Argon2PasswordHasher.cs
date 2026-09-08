using CistaNAS.Web.Configuration;
using CistaNAS.Web.Crypto;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Identity;

/// <summary>
/// ログインパスワードのハッシュ化・検証。
/// 新規ハッシュは Argon2id（メモリ困難性、PHC 形式）。検証時は旧形式も受け付ける:
/// - <c>$argon2id$...</c> : 現行 Argon2id
/// - <c>pbkdf2-sha256$...</c> : 初期リリースの PBKDF2-SHA256（<see cref="PasswordHasher"/>）
/// - 上記以外 : ASP.NET Core Identity V3 形式（PBKDF2-SHA512）
/// 旧形式の検証成功は <see cref="PasswordVerificationResult.SuccessRehashNeeded"/> を返し、
/// UserManager が次回ログイン時に Argon2id へ透過的に再ハッシュする。
/// </summary>
public sealed class Argon2PasswordHasher : IPasswordHasher<ApplicationUser>
{
    private const string LegacyPbkdf2Prefix = "pbkdf2-sha256";

    private readonly PasswordHasher<ApplicationUser> _identityV3Hasher = new();
    private readonly CistaNasOptions _options;

    public Argon2PasswordHasher(IOptions<CistaNasOptions> options)
    {
        _options = options.Value;
    }

    public string HashPassword(ApplicationUser user, string password)
    {
        var auth = _options.Auth;
        return Argon2Hasher.Hash(password, auth.Argon2TimeCost, auth.Argon2MemoryKiB, auth.Argon2Parallelism);
    }

    public PasswordVerificationResult VerifyHashedPassword(
        ApplicationUser user, string hashedPassword, string providedPassword)
    {
        if (string.IsNullOrEmpty(hashedPassword) || string.IsNullOrEmpty(providedPassword))
            return PasswordVerificationResult.Failed;

        if (hashedPassword.StartsWith(Argon2Hasher.Prefix, StringComparison.Ordinal))
        {
            // パラメータ上限超過などは Verify 内で false 扱い（改ざん DoS 対策）
            return Argon2Hasher.Verify(providedPassword, hashedPassword)
                ? PasswordVerificationResult.Success
                : PasswordVerificationResult.Failed;
        }

        if (hashedPassword.StartsWith(LegacyPbkdf2Prefix + "$", StringComparison.Ordinal))
        {
            try
            {
                bool valid = PasswordHasher.Verify(providedPassword, hashedPassword);
                return valid
                    ? PasswordVerificationResult.SuccessRehashNeeded
                    : PasswordVerificationResult.Failed;
            }
            catch (FormatException)
            {
                return PasswordVerificationResult.Failed;
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                return PasswordVerificationResult.Failed;
            }
        }

        return _identityV3Hasher.VerifyHashedPassword(user, hashedPassword, providedPassword);
    }
}
