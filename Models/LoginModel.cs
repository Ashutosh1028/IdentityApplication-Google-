using System.ComponentModel.DataAnnotations;

namespace IdentityApplication.Models
{
    public class LoginModel
    {
        [Required]
        public string Email {  get; set; }=string.Empty;
        [Required]
        public string Password { get; set; }= string.Empty;
        [Required]
        public bool RememberMe { get; set; }
        [Required]
        public string ReturnUrl { get; set; } = "/";
    }
}
