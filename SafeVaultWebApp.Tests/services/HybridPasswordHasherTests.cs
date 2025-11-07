using Xunit;
using Microsoft.AspNetCore.Identity;

namespace SafeVaultWebApp.Tests.Services
{
    public class HybridPasswordHasherTests
    {
        private readonly HybridPasswordHasher<IdentityUser> _hasher;

        public HybridPasswordHasherTests()
        {
            _hasher = new HybridPasswordHasher<IdentityUser>();
        }

        [Fact]
        public void HashPassword_ShouldReturnBcryptFormattedHash()
        {
            var user = new IdentityUser();
            var password = "SecurePass123!";
            var hash = _hasher.HashPassword(user, password);

            Assert.StartsWith("$2", hash); // bcrypt hashes start with $2a$, $2b$, or $2y$
        }

        [Fact]
        public void VerifyHashedPassword_WithBcryptHash_ShouldSucceed()
        {
            var user = new IdentityUser();
            var password = "SecurePass123!";
            var hash = BCrypt.Net.BCrypt.HashPassword(password);

            var result = _hasher.VerifyHashedPassword(user, hash, password);

            Assert.Equal(PasswordVerificationResult.Success, result);
        }

        [Fact]
        public void VerifyHashedPassword_WithBcryptHash_ShouldFailForWrongPassword()
        {
            var user = new IdentityUser();
            var hash = BCrypt.Net.BCrypt.HashPassword("CorrectPassword");

            var result = _hasher.VerifyHashedPassword(user, hash, "WrongPassword");

            Assert.Equal(PasswordVerificationResult.Failed, result);
        }

        [Fact]
        public void VerifyHashedPassword_WithPBKDF2Hash_ShouldSucceed()
        {
            var user = new IdentityUser();
            var fallbackHasher = new PasswordHasher<IdentityUser>();
            var password = "LegacyPassword!";
            var hash = fallbackHasher.HashPassword(user, password);

            var result = _hasher.VerifyHashedPassword(user, hash, password);

            Assert.Equal(PasswordVerificationResult.Success, result);
        }

        [Fact]
        public void VerifyHashedPassword_WithPBKDF2Hash_ShouldFailForWrongPassword()
        {
            var user = new IdentityUser();
            var fallbackHasher = new PasswordHasher<IdentityUser>();
            var hash = fallbackHasher.HashPassword(user, "CorrectPassword");

            var result = _hasher.VerifyHashedPassword(user, hash, "WrongPassword");

            Assert.Equal(PasswordVerificationResult.Failed, result);
        }
    }
}
