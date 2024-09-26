using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityApplication.Models
{
    public class EmployeeExternalModel
    {

        [Required]
        public string Name { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }


        [Required]
        [Phone]
        public string Phone { get; set; }
        [Required(ErrorMessage = "Please select a Role.")]
        [CustomValidation(typeof(EmployeeModel), "ValidateRoleSelection")]
        public string Role { get; set; }


        public static ValidationResult ValidateRoleSelection(string role, ValidationContext context)
        {
            if (role == "0" || string.IsNullOrWhiteSpace(role))
            {
                return new ValidationResult("Please select a Role.");
            }

            return ValidationResult.Success;
        }


        public string ReturnUrl { get; set; } = "/";
    }
}