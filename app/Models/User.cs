using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace AuthApi.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string Username { get; set; }

        [Required]
        [EmailAddress]
        [MaxLength(150)]
        public string Email { get; set; }

        [Required]
        public string PasswordHash { get; set; }

        // Default role is "User"
        [Required]
        [MaxLength(50)]
        public string Role { get; set; } = "User";

        public List<RefreshToken> RefreshTokens { get; set; } = new();
    }
}
