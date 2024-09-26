using IdentityApplication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;
using System.Security.Claims;

namespace IdentityApplication.Controllers
{
    [AllowAnonymous]
    public class ExternalLoginController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _dbContext;

        public ExternalLoginController(
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ApplicationDbContext dbContext)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _roleManager = roleManager;
            _dbContext = dbContext;
        }

       

        public IActionResult Challenge(string provider, string returnUrl = null)
        {
            var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "ExternalLogin", new { ReturnUrl = returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            if (remoteError != null)
            {
                // Handle error
                return RedirectToAction(nameof(Login), new { ReturnUrl = returnUrl });
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction("Login","Verify");
            }
            var user = await _userManager.FindByEmailAsync(info.Principal.FindFirstValue(ClaimTypes.Email));
            if (user != null)
            {
                // If the user already exists, sign them in
                await _signInManager.SignInAsync(user, isPersistent: false);
                return Redirect(returnUrl);
            }

            var externalLoginModel = new EmployeeExternalModel
            {
                ReturnUrl = returnUrl,
                Email = info.Principal.FindFirstValue(ClaimTypes.Email),
                Name = info.Principal.FindFirstValue(ClaimTypes.Name)
            };

            var roles = await _roleManager.Roles.ToListAsync();
            ViewBag.Roles = roles;

            return View("ExternalRegister", externalLoginModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalRegister(EmployeeExternalModel model)
        {
            if (ModelState.IsValid)
            {
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return RedirectToAction("Login", "Verify");
                }
                var name = model.Name.Split(' ');
                var user = new IdentityUser
                {
                    UserName = name[0],
                    Email = model.Email,
                    PhoneNumber = model.Phone
                };

                var result = await _userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    var data = new Employee
                    {
                        Name = model.Name,
                        Email = model.Email,
                        Password ="External Login",
                        Phone = model.Phone,
                        Role = model.Role
                    };
                    await _dbContext.Employees.AddAsync(data);
                    await _dbContext.SaveChangesAsync();

                    await _userManager.AddLoginAsync(user, info);
                    if (!string.IsNullOrEmpty(model.Role))
                    {
                        await _userManager.AddToRoleAsync(user, model.Role);
                    }
                    await _signInManager.SignInAsync(user, isPersistent: false);

                    return Redirect(model.ReturnUrl ?? "/");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            var roles = await _roleManager.Roles.ToListAsync();
            ViewBag.Roles = roles;
            return View(model);
        }
    }
}
