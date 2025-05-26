using Microsoft.AspNetCore.Mvc;

namespace OdevPortalUI.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Login() => View();
        public IActionResult Register() => View();
        public IActionResult Logout()
        {
            // Sadece client tarafı localStorage temizlenecek, fakat yine de yönlendirme için bırakıldı.
            return RedirectToAction("Login");
        }
    }
}