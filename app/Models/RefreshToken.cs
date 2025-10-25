using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthApi.Models
{
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }

        public string Token { get; set; }

        public DateTime Expires { get; set; }

        public DateTime Created { get; set; }

        public DateTime? Revoked { get; set; }

        [ForeignKey(nameof(User))]
        public int UserId { get; set; }
        public User User { get; set; }

        public bool IsActive => Revoked == null && !IsExpired;
        public bool IsExpired => DateTime.UtcNow >= Expires;
    }
}
