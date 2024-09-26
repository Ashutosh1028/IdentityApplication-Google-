using IdentityApplication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;

namespace IdentityApplication.Controllers
{
    public class VerifyController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ApplicationDbContext _dbContext;
        private readonly RoleManager<IdentityRole> _roleManager;

        public VerifyController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, ApplicationDbContext dbContext, RoleManager<IdentityRole> roleManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _dbContext = dbContext;
            _roleManager = roleManager;
        }
        public IActionResult Login(string ReturnUrl = "/")
        {
            LoginModel loginmodel = new()
            {
                ReturnUrl = ReturnUrl
            };
            return View(loginmodel);
        }
        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
                {

                    var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: false);
                    if (result.Succeeded)
                    {
                        var returnurl = model.ReturnUrl;
                        if (string.IsNullOrEmpty(returnurl))
                            return RedirectToAction("Index", "Home");
                        else
                            return Redirect(returnurl);

                    }
                    else if (result.IsLockedOut)
                    {
                        ModelState.AddModelError(string.Empty, "Your account is locked out. Please try again later.");
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, "Invalid Credentials.");
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid Credentials.");
                }
            }

            return View(model);
        }


        [HttpGet]
        public async Task<IActionResult> Register(string ReturnUrl = "/")
        {
            var roles = await _roleManager.Roles.ToListAsync();
            ViewBag.Roles = roles;

            var model = new EmployeeModel
            {
                ReturnUrl = ReturnUrl
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(EmployeeModel model)
        {
            if (ModelState.IsValid)
            {
                var name = model.Name.Split(' ');
                var user = new IdentityUser
                {
                    UserName = name[0],
                    Email = model.Email,
                    PhoneNumber = model.Phone
                };

                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    var data = new Employee
                    {
                        Name = model.Name,
                        Email = model.Email,
                        Password = model.Password,
                        Phone = model.Phone,
                        Role = model.Role
                    };
                    await _dbContext.Employees.AddAsync(data);
                    await _dbContext.SaveChangesAsync();
                    if (!string.IsNullOrEmpty(model.Role))
                    {
                        await _userManager.AddToRoleAsync(user, model.Role);
                    }
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    var returnurl = model.ReturnUrl;
                    if (string.IsNullOrEmpty(returnurl))
                        return RedirectToAction("Index", "Home");
                    else
                        return Redirect(returnurl);
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
        [Authorize(Roles ="Admin")]
        [HttpGet]
        public async Task<IActionResult> Create()
        {
            var roles = await _roleManager.Roles.ToListAsync();
            ViewBag.Roles = roles;


            return View();
        }

        [Authorize(Roles = "Admin")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(EmployeeModel model)
        {
            if (ModelState.IsValid)
            {
                var name = model.Name.Split(' ');
                var user = new IdentityUser
                {
                    UserName = name[0],
                    Email = model.Email,
                    PhoneNumber = model.Phone
                };

                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    var data = new Employee
                    {
                        Name = model.Name,
                        Email = model.Email,
                        Password = model.Password,
                        Phone = model.Phone,
                        Role = model.Role
                    };
                    await _dbContext.Employees.AddAsync(data);
                    await _dbContext.SaveChangesAsync();
                    if (!string.IsNullOrEmpty(model.Role))
                    {
                        await _userManager.AddToRoleAsync(user, model.Role);
                    }
                    return RedirectToAction("EmpList", "Home");
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
        [HttpGet]
        public async Task<IActionResult> EditProfile(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return RedirectToAction("Login");
            }
            var data = await _dbContext.Employees.FirstOrDefaultAsync(m => m.Email == user.Email);
            if (data == null)
            {
                return RedirectToAction("Login");
            }
            var model = new EditProfileModel
            {
                Name = data.Name,
                Email = data.Email,
                Phone = data.Phone
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditProfile(EditProfileModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return RedirectToAction("Login");
            }
            var curuser = await _userManager.GetUserAsync(User);
            bool isSameUser = curuser?.Email == user.Email;

            user.UserName = model.Name.Split(" ")[0];
            user.Email = model.Email;
            user.PhoneNumber = model.Phone;

            var result = await _userManager.UpdateAsync(user);
            if (result.Succeeded)
            {
                //var currentRoles = await _userManager.GetRolesAsync(user);

                //await _userManager.RemoveFromRolesAsync(user, currentRoles);
                //if (!await _roleManager.RoleExistsAsync(newRole))
                //{
                //    TempData["ErrorMessage"] = "Role does not exist.";
                //    return RedirectToAction("Index");
                //}
                var employee = await _dbContext.Employees.FirstOrDefaultAsync(e => e.Email == user.Email);
                if (employee != null)
                {
                    employee.Name = model.Name;
                    employee.Email = model.Email;
                    employee.Phone = model.Phone;
                    await _dbContext.SaveChangesAsync();
                }
                if (isSameUser)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);

                }

                TempData["SuccessMessage"] = "Profile updated successfully.";
                return RedirectToAction("Index", "Home");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }
        [HttpGet]
        public async Task<IActionResult> DeleteAccount(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            var model = new DeleteAccountModel
            {
                Email = user.Email
            };

            return View(model);
        }

        [HttpPost, ActionName("DeleteAccount")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ConfirmDeleteAccount(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            
            if (user == null)
            {
                return RedirectToAction("Login");
            }
            var curuser = await _userManager.GetUserAsync(User);
            bool isSameUser = curuser?.Email == user.Email;

            var result = await _userManager.DeleteAsync(user);
            if (result.Succeeded)
            {
                var employee = await _dbContext.Employees.FirstOrDefaultAsync(e => e.Email == user.Email);
                if (employee != null)
                {
                    _dbContext.Employees.Remove(employee);
                    await _dbContext.SaveChangesAsync();
                }

                if(isSameUser)
                    await _signInManager.SignOutAsync();

                TempData["SuccessMessage"] = "Your account has been deleted.";
                return RedirectToAction("Index", "Home");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
        public async Task<IActionResult> AccessDenied()
        {
            return View();
        }
    }
}

