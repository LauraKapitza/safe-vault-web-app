using Microsoft.AspNetCore.Identity;
using System;
using System.Threading.Tasks;

namespace SafeVaultWebApp.Web.Services
{
    public static class Seeder
    {
        public static async Task SeedRolesAsync(RoleManager<IdentityRole> roleManager)
        {
            string[] roles = { "Admin", "User" };

            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    await roleManager.CreateAsync(new IdentityRole(role));
                    Console.WriteLine($"Role '{role}' created.");
                }
            }
        }

        public static async Task SeedAdminUserAsync(UserManager<IdentityUser> userManager)
        {
            string adminEmail = Environment.GetEnvironmentVariable("ADMIN_EMAIL");
            string adminPassword = Environment.GetEnvironmentVariable("ADMIN_PASSWORD");

            if (string.IsNullOrWhiteSpace(adminPassword))
            {
                Console.WriteLine("Admin password not set. Skipping admin user creation.");
                return;
            }

            var adminUser = await userManager.FindByEmailAsync(adminEmail);
            if (adminUser == null)
            {
                var user = new IdentityUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(user, adminPassword);
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "Admin");
                    Console.WriteLine("Admin account created and assigned to 'Admin' role.");
                }
                else
                {
                    Console.WriteLine("Failed to create admin account:");
                    foreach (var error in result.Errors)
                    {
                        Console.WriteLine($" - {error.Description}");
                    }
                }
            }
            else
            {
                Console.WriteLine("Admin account already exists.");
            }
        }
    }
}
