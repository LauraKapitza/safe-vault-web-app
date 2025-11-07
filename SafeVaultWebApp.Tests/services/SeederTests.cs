using Xunit;
using Moq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using SafeVaultWebApp.Web.Services;
using System.Collections.Generic;
using System.Security.Claims;

namespace SafeVaultWebApp.Tests.Services
{
    public class SeederTests
    {
        [Fact]
        public async Task SeedRolesAsync_ShouldCreateMissingRoles()
        {
            var roleStore = new Mock<IRoleStore<IdentityRole>>();
            var roleManager = new Mock<RoleManager<IdentityRole>>(
                roleStore.Object, null, null, null, null);

            roleManager.Setup(r => r.RoleExistsAsync("Admin")).ReturnsAsync(false);
            roleManager.Setup(r => r.RoleExistsAsync("User")).ReturnsAsync(false);
            roleManager.Setup(r => r.CreateAsync(It.IsAny<IdentityRole>()))
                .ReturnsAsync(IdentityResult.Success);

            await Seeder.SeedRolesAsync(roleManager.Object);

            roleManager.Verify(r => r.CreateAsync(It.Is<IdentityRole>(role => role.Name == "Admin")), Times.Once);
            roleManager.Verify(r => r.CreateAsync(It.Is<IdentityRole>(role => role.Name == "User")), Times.Once);
        }

        [Fact]
        public async Task SeedRolesAsync_ShouldSkipExistingRoles()
        {
            var roleStore = new Mock<IRoleStore<IdentityRole>>();
            var roleManager = new Mock<RoleManager<IdentityRole>>(
                roleStore.Object, null, null, null, null);

            roleManager.Setup(r => r.RoleExistsAsync(It.IsAny<string>())).ReturnsAsync(true);

            await Seeder.SeedRolesAsync(roleManager.Object);

            roleManager.Verify(r => r.CreateAsync(It.IsAny<IdentityRole>()), Times.Never);
        }

        [Fact]
        public async Task SeedAdminUserAsync_ShouldSkipIfPasswordMissing()
        {
            Environment.SetEnvironmentVariable("ADMIN_PASSWORD", "");

            var userStore = new Mock<IUserStore<IdentityUser>>();
            var userManager = new Mock<UserManager<IdentityUser>>(
                userStore.Object, null, null, null, null, null, null, null, null);

            await Seeder.SeedAdminUserAsync(userManager.Object);

            userManager.Verify(u => u.CreateAsync(It.IsAny<IdentityUser>(), It.IsAny<string>()), Times.Never);
        }

        [Fact]
        public async Task SeedAdminUserAsync_ShouldCreateUserAndAssignRole()
        {
            Environment.SetEnvironmentVariable("ADMIN_EMAIL", "admin@safevault.com");
            Environment.SetEnvironmentVariable("ADMIN_PASSWORD", "SecureAdmin123!");

            var userStore = new Mock<IUserStore<IdentityUser>>();
            var userManager = new Mock<UserManager<IdentityUser>>(
                userStore.Object, null, null, null, null, null, null, null, null);

            userManager.Setup(u => u.FindByEmailAsync("admin@safevault.com")).ReturnsAsync((IdentityUser)null);
            userManager.Setup(u => u.CreateAsync(It.IsAny<IdentityUser>(), "SecureAdmin123!"))
                .ReturnsAsync(IdentityResult.Success);
            userManager.Setup(u => u.AddToRoleAsync(It.IsAny<IdentityUser>(), "Admin"))
                .ReturnsAsync(IdentityResult.Success);

            await Seeder.SeedAdminUserAsync(userManager.Object);

            userManager.Verify(u => u.CreateAsync(It.Is<IdentityUser>(user => user.Email == "admin@safevault.com"), "SecureAdmin123!"), Times.Once);
            userManager.Verify(u => u.AddToRoleAsync(It.IsAny<IdentityUser>(), "Admin"), Times.Once);
        }

        [Fact]
        public async Task SeedAdminUserAsync_ShouldSkipIfUserAlreadyExists()
        {
            Environment.SetEnvironmentVariable("ADMIN_EMAIL", "admin@safevault.com");
            Environment.SetEnvironmentVariable("ADMIN_PASSWORD", "SecureAdmin123!");

            var existingUser = new IdentityUser { Email = "admin@safevault.com" };

            var userStore = new Mock<IUserStore<IdentityUser>>();
            var userManager = new Mock<UserManager<IdentityUser>>(
                userStore.Object, null, null, null, null, null, null, null, null);

            userManager.Setup(u => u.FindByEmailAsync("admin@safevault.com")).ReturnsAsync(existingUser);

            await Seeder.SeedAdminUserAsync(userManager.Object);

            userManager.Verify(u => u.CreateAsync(It.IsAny<IdentityUser>(), It.IsAny<string>()), Times.Never);
            userManager.Verify(u => u.AddToRoleAsync(It.IsAny<IdentityUser>(), It.IsAny<string>()), Times.Never);
        }
    }
}
