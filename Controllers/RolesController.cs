using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApplication.Controllers
{
    [Authorize(Roles = "Admin")]
    public class RolesController : Controller
    {
        private readonly RoleManager<IdentityRole> _manager;
        public RolesController(RoleManager<IdentityRole> manager)
        {
            _manager = manager;
        }
        public IActionResult Index()
        {
            var roles = _manager.Roles;
            return View(roles);
        }
        public IActionResult Create()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Create(IdentityRole model)
        {
            if (!await _manager.RoleExistsAsync(model.Name))
            {
               await _manager.CreateAsync(new IdentityRole(model.Name));
            }
            return RedirectToAction("Index");
        }
    }
}
