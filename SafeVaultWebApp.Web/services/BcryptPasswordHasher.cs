using Microsoft.AspNetCore.Identity;
using BCrypt.Net;

public class HybridPasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
{
    private readonly PasswordHasher<TUser> _fallbackHasher = new PasswordHasher<TUser>();

    public string HashPassword(TUser user, string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password);
    }

    public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
    {
        if (IsBcryptHash(hashedPassword))
        {
            return BCrypt.Net.BCrypt.Verify(providedPassword, hashedPassword)
                ? PasswordVerificationResult.Success
                : PasswordVerificationResult.Failed;
        }

        // Fallback to default Identity hasher (PBKDF2)
        return _fallbackHasher.VerifyHashedPassword(user, hashedPassword, providedPassword);
    }

    private bool IsBcryptHash(string hash)
    {
        return hash.StartsWith("$2a$") || hash.StartsWith("$2b$") || hash.StartsWith("$2y$");
    }
}
