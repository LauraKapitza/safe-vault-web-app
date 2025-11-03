using Xunit;
using Moq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using Ganss.Xss;
using SafeVaultWebApp.Web.Controllers;
using SafeVaultWebApp.Web.Models;
using IdentitySignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace SafeVaultWebApp.Tests.Controllers
{
    public class UserAccountControllerTests
    {
        private readonly UserAccountController _controller;
        private readonly Mock<UserManager<IdentityUser>> _userManager;
        private readonly Mock<SignInManager<IdentityUser>> _signInManager;

        public UserAccountControllerTests()
        {
            var userStore = new Mock<IUserStore<IdentityUser>>();
            _userManager = new Mock<UserManager<IdentityUser>>(
                userStore.Object, null, null, null, null, null, null, null, null
            );

            var contextAccessor = new Mock<IHttpContextAccessor>();
            var claimsFactory = new Mock<IUserClaimsPrincipalFactory<IdentityUser>>();
            _signInManager = new Mock<SignInManager<IdentityUser>>(
                _userManager.Object,
                contextAccessor.Object,
                claimsFactory.Object,
                null, null, null, null
            );

            var logger = new Mock<ILogger<UserAccountController>>();
            var sanitizer = new HtmlSanitizer();

            _controller = new UserAccountController(_userManager.Object, _signInManager.Object, logger.Object, sanitizer);
        }

        [Fact]
        public async Task Register_ShouldRejectSqlInjection()
        {
            var model = new RegisterViewModel
            {
                Email = "'; DROP TABLE Users; --",
                Password = "SafePass123!",
                ConfirmPassword = "SafePass123!"
            };

            _userManager.Setup(x => x.CreateAsync(It.IsAny<IdentityUser>(), model.Password))
                .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Invalid email format." }));

            var result = await _controller.Register(model);

            var viewResult = Assert.IsType<ViewResult>(result);
            Assert.False(viewResult.ViewData.ModelState.IsValid);
        }

        [Fact]
        public async Task Register_WithValidInput_ShouldRedirectToLogin()
        {
            var model = new RegisterViewModel
            {
                Email = "test@example.com",
                Password = "StrongPass123!",
                ConfirmPassword = "StrongPass123!"
            };

            _userManager.Setup(x => x.CreateAsync(It.IsAny<IdentityUser>(), model.Password))
                .ReturnsAsync(IdentityResult.Success);

            var result = await _controller.Register(model);

            var redirect = Assert.IsType<RedirectToActionResult>(result);
            Assert.Equal("Login", redirect.ActionName);
            Assert.Equal("UserAccount", redirect.ControllerName);
        }

        [Fact]
        public async Task Register_ShouldSanitizeEmailInput()
        {
            var model = new RegisterViewModel
            {
                Email = "<script>alert('xss')</script>",
                Password = "SafePass123!",
                ConfirmPassword = "SafePass123!"
            };

            IdentityUser capturedUser = null;

            _userManager.Setup(x => x.CreateAsync(It.IsAny<IdentityUser>(), model.Password))
                .Callback<IdentityUser, string>((user, _) => capturedUser = user)
                .ReturnsAsync(IdentityResult.Success);

            var result = await _controller.Register(model);

            var redirect = Assert.IsType<RedirectToActionResult>(result);
            Assert.Equal("Login", redirect.ActionName);
            Assert.NotNull(capturedUser);
            Assert.Equal("", capturedUser.Email);
        }

        [Fact]
        public async Task Login_WithValidCredentials_ShouldRedirectToHome()
        {
            var model = new LoginViewModel
            {
                Email = "user@example.com",
                Password = "Password123!",
                RememberMe = false
            };

            _signInManager.Setup(x => x.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false))
                .ReturnsAsync(IdentitySignInResult.Success);

            var result = await _controller.Login(model);

            var redirect = Assert.IsType<RedirectToActionResult>(result);
            Assert.Equal("Index", redirect.ActionName);
            Assert.Equal("Home", redirect.ControllerName);
        }

        [Fact]
        public async Task Login_WithInvalidCredentials_ShouldReturnViewWithError()
        {
            var model = new LoginViewModel
            {
                Email = "user@example.com",
                Password = "WrongPassword!",
                RememberMe = false
            };

            _signInManager.Setup(x => x.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false))
                .ReturnsAsync(IdentitySignInResult.Failed);

            var result = await _controller.Login(model);

            var viewResult = Assert.IsType<ViewResult>(result);
            Assert.False(viewResult.ViewData.ModelState.IsValid);
            Assert.Contains("Invalid login attempt.", viewResult.ViewData.ModelState[string.Empty].Errors[0].ErrorMessage);
        }

        [Fact]
        public async Task Logout_ShouldRedirectToHome()
        {
            var result = await _controller.Logout();

            var redirect = Assert.IsType<RedirectToActionResult>(result);
            Assert.Equal("Index", redirect.ActionName);
            Assert.Equal("Home", redirect.ControllerName);
        }
    }
}
