using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

[Authorize(Roles = "Admin")] // restrict access to role management
public class RolesController : Controller
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<IdentityUser> _userManager;

    public RolesController(RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
    {
        _roleManager = roleManager;
        _userManager = userManager;
    }

    // Create a new role
    [HttpPost]
    public async Task<IActionResult> CreateRole(string roleName)
    {
        if (string.IsNullOrWhiteSpace(roleName))
        {
            return BadRequest("Role name cannot be empty.");
        }

        if (!await _roleManager.RoleExistsAsync(roleName))
        {
            var result = await _roleManager.CreateAsync(new IdentityRole(roleName));
            if (result.Succeeded)
                return Ok($"Role '{roleName}' created successfully.");
            return BadRequest(result.Errors);
        }

        return Ok("Role already exists.");
    }

    // Assign a role to a user
    [HttpPost]
    public async Task<IActionResult> AssignRoleToUser(string email, string roleName)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null) return NotFound("User not found.");

        if (!await _roleManager.RoleExistsAsync(roleName))
            return BadRequest("Role does not exist.");

        var result = await _userManager.AddToRoleAsync(user, roleName);
        if (result.Succeeded)
            return Ok($"User '{email}' assigned to role '{roleName}'.");

        return BadRequest(result.Errors);
    }

    // Verify role assignment
    [HttpGet]
    public async Task<IActionResult> CheckUserRole(string email, string roleName)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null) return NotFound("User not found.");

        bool isInRole = await _userManager.IsInRoleAsync(user, roleName);
        return Ok(isInRole ? $"{email} is in role {roleName}." : $"{email} is not in role {roleName}.");
    }
}
