namespace AuthApi.Dtos
{
    public class RegisterRequest
    {
        public string Username { get; set; }
        public string Email { get; set; }   // ✅ Added email
        public string Password { get; set; }
        public string Role { get; set; } = "User"; // default user
    }
}
