using Microsoft.AspNetCore.Mvc;

namespace SafeVaultWebApp.Web.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
