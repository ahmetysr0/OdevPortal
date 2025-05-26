using OdevPortalAPI.DTOs;
using OdevPortalAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using OdevPortalAPI.Models;

namespace OdevPortalAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authService;
        private readonly UserManager<AppUser> _userManager;

        public AuthController(AuthService authService, UserManager<AppUser> userManager)
        {
            _authService = authService;
            _userManager = userManager;
        }


        // User giriş metodu
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO model)
        {
            var token = await _authService.LoginAsync(model);
            if (token == null)
                return Unauthorized(new { Message = "Invalid username or password" });

            return Ok(token);
        }

        // User kayıt metodu
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO model)
        {
            var result = await _authService.RegisterAsync(model);
            if (!result.Succeeded)
                return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });

            return Ok(new { Message = "User registered successfully" });
        }

        // Admin rol ekleme metodu
        [Authorize(Roles = "Admin")]
        [HttpPost("add-to-role")]
        public async Task<IActionResult> AddToRole(string userId, string role)
        {
            var result = await _authService.AddToRoleAsync(userId, role);
            if (!result.Succeeded)
                return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });

            return Ok(new { Message = "Role added successfully" });
        }

        // Admin rol kaldırma metodu
        [Authorize(Roles = "Admin")]
        [HttpPost("remove-from-role")]
        public async Task<IActionResult> RemoveFromRole(string userId, string role)
        {
            var result = await _authService.RemoveFromRoleAsync(userId, role);
            if (!result.Succeeded)
                return BadRequest(new { Errors = result.Errors.Select(e => e.Description) });

            return Ok(new { Message = "Role removed successfully" });
        }

        [Authorize]
        [HttpGet("userinfo")]
        public async Task<IActionResult> GetUserInfo()
        {
            var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized(new { Message = "Kullanıcı kimliği bulunamadı." });

            var appUser = await _userManager.FindByIdAsync(userId);
            if (appUser == null)
                return NotFound(new { Message = "Kullanıcı bulunamadı." });

            var roles = await _userManager.GetRolesAsync(appUser);

            return Ok(new
            {
                userName = appUser.UserName,
                email = appUser.Email,
                roles = roles
            });
        }
        [Authorize]
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword(ChangePasswordDTO model)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return Unauthorized();

            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!result.Succeeded)
                return BadRequest(new { message = string.Join(", ", result.Errors.Select(x => x.Description)) });

            return Ok(new { message = "Şifre başarıyla değiştirildi." });
        }
        [Authorize]
        [HttpPut("update-profile")]
        public async Task<IActionResult> UpdateProfile(UpdateProfileDTO model)
        {
            var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return Unauthorized();

            if (!string.IsNullOrEmpty(model.NewUserName))
                user.UserName = model.NewUserName;

            if (!string.IsNullOrEmpty(model.NewEmail))
                user.Email = model.NewEmail;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
                return BadRequest(new { message = string.Join(", ", result.Errors.Select(x => x.Description)) });

            return Ok(new { message = "Profil başarıyla güncellendi." });
        }
        // Admin: Belirli bir kullanıcıyı ve rollerini dönen endpoint
        [HttpGet("users/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetUserById(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { Message = "Kullanıcı bulunamadı." });

            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new
            {
                id = user.Id,
                userName = user.UserName,
                email = user.Email,
                roles = roles
            });
        }
        // Admin: Kullanıcıyı güncelle
        [HttpPut("users/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateUser(string id, [FromBody] UpdateUserDTO model)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { Message = "Kullanıcı bulunamadı." });

            // Değiştirilecek alanları güncelle
            if (!string.IsNullOrEmpty(model.UserName))
                user.UserName = model.UserName;
            if (!string.IsNullOrEmpty(model.Email))
                user.Email = model.Email;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
                return BadRequest(new { message = string.Join(", ", result.Errors.Select(x => x.Description)) });

            // Eğer rol de güncellenecekse:
            if (model.Roles != null && model.Roles.Any())
            {
                var currentRoles = await _userManager.GetRolesAsync(user);
                await _userManager.RemoveFromRolesAsync(user, currentRoles);
                await _userManager.AddToRolesAsync(user, model.Roles);
            }

            return Ok(new { message = "Kullanıcı başarıyla güncellendi." });
        }
        // Admin: Kullanıcının rollerini güncelle
        [HttpPut("users/{id}/roles")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateUserRoles(string id, [FromBody] List<string> roles)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { Message = "Kullanıcı bulunamadı." });

            var currentRoles = await _userManager.GetRolesAsync(user);
            // Mevcut rolleri sil
            var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);
            if (!removeResult.Succeeded)
                return BadRequest(new { message = "Roller silinirken hata oluştu: " + string.Join(", ", removeResult.Errors.Select(x => x.Description)) });

            // Yeni rolleri ekle
            var addResult = await _userManager.AddToRolesAsync(user, roles);
            if (!addResult.Succeeded)
                return BadRequest(new { message = "Roller eklenirken hata oluştu: " + string.Join(", ", addResult.Errors.Select(x => x.Description)) });

            return Ok(new { message = "Kullanıcı rolleri başarıyla güncellendi." });
        }

        // Admin: Tüm kullanıcıları ve rollerini dönen endpoint (UI admin paneli için)
        [HttpGet("users")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetUsers()
        {
            var users = await _authService.GetAllUsersAsync();
            var userList = new List<object>();
            foreach (var user in users)
            {
                var roles = await _authService.GetRolesAsync(user);
                userList.Add(new
                {
                    id = user.Id, // <-- Bunu ekledik!
                    userName = user.UserName,
                    email = user.Email,
                    roles = roles
                });
            }
            return Ok(userList);
        }

        // (İsteğe bağlı) Eski endpointi kaldırdım, yukarıdaki userinfo ve users endpointleri tüm UI için yeterlidir.
    }
}