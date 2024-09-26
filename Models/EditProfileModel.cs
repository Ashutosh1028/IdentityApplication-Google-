using System.ComponentModel.DataAnnotations;

namespace IdentityApplication.Models
{
    public class EditProfileModel
    {
        [Required]
        public string Name { get; set; }

        [Required, EmailAddress]
        public string Email { get; set; }

        [Phone]
        public string Phone { get; set; }
    }

    public class DeleteAccountModel
    {
        public string Email { get; set; }
    }

}
