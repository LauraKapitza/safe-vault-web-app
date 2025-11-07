using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using SafeVaultWebApp.Web.Models;
using Ganss.Xss;


public class UserAccountController : Controller
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<UserAccountController> _logger;
    private readonly HtmlSanitizer _sanitizer;
    private readonly IPasswordHasher<IdentityUser> _passwordHasher;

    public UserAccountController(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        ILogger<UserAccountController> logger,
        HtmlSanitizer sanitizer,
        IPasswordHasher<IdentityUser> passwordHasher
    )
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
        _sanitizer = sanitizer;
        _passwordHasher = passwordHasher;
    }

    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }

    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (model == null)
        {
            _logger.LogError("Register model was null.");
            return BadRequest("Invalid registration data.");
        }
        // Sanitize user input
        model.Email = _sanitizer.Sanitize(model.Email ?? string.Empty);

        if (!ModelState.IsValid)
        {
            return View(model);
        }
        var user = new IdentityUser { UserName = model.Email, Email = model.Email };
        var result = await _userManager.CreateAsync(user, model.Password);
        _logger.LogInformation("CreateAsync succeeded: {Succeeded}", result.Succeeded);

        if (result.Succeeded)
        {
            _logger.LogInformation("User created a new account with email {Email}.", model.Email);
            return RedirectToAction(nameof(Login), "UserAccount");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
            _logger.LogError("Register error: {Error}", error.Description);
        }

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        // Sanitize user input
        model.Email = _sanitizer.Sanitize(model.Email ?? string.Empty);

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }

        var result = await _signInManager.PasswordSignInAsync(
            user.UserName, model.Password, model.RememberMe, lockoutOnFailure: false);

        if (result.Succeeded)
        {
            var currentHash = user.PasswordHash;
            //check whether user's password hasn't been yet hashed by bcrypt.
            if (currentHash != null && !currentHash.StartsWith("$2")) // not bcrypt
            {
                // Rehash password with bcrypt
                await _userManager.RemovePasswordAsync(user);
                await _userManager.AddPasswordAsync(user, model.Password);
                _logger.LogInformation("Password rehashed to bcrypt for user {Email}.", model.Email);
            }

            // Assign "User" role if user has no roles
            var roles = await _userManager.GetRolesAsync(user);
            if (roles == null || roles.Count == 0)
            {
                await _userManager.AddToRoleAsync(user, "User");
                _logger.LogInformation("Assigned 'User' role to {Email}.", model.Email);
            }

            _logger.LogInformation("User {Email} logged in.", model.Email);
            
            // Redirect based on role
            if (roles.Contains("Admin"))
            {
                return RedirectToAction("Dashboard", "Admin");
            }
            else if (roles.Contains("User"))
            {
                return RedirectToAction("Index", "Home");
            }
            else
            {
                return RedirectToAction("Index", "Home"); // fallback
            }
        }

        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        _logger.LogInformation("User logged out.");
        return RedirectToAction("Index", "Home");
    }
}