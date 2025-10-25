using System.Linq;
using System.Threading.Tasks;
using AuthApi.Data;
using AuthApi.Dtos;
using AuthApi.Models;
using AuthApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _db;
        private readonly ITokenService _tokenService;

        public AuthController(AppDbContext db, ITokenService tokenService)
        {
            _db = db;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest req)
        {
            if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
                return BadRequest("Username and password required.");

            if (await _db.Users.AnyAsync(u => u.Username == req.Username))
                return BadRequest("Username already taken.");

            var user = new User
{
    Username = req.Username,
    Email = req.Email,
    PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.Password),
    Role = string.IsNullOrWhiteSpace(req.Role) ? "User" : req.Role
};


            _db.Users.Add(user);
            await _db.SaveChangesAsync();

            return Ok(new { message = "Registered" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest req)
        {
            var user = await _db.Users.Include(u => u.RefreshTokens)
                                     .SingleOrDefaultAsync(u => u.Username == req.Username);

            if (user == null || !BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash))
                return Unauthorized("Invalid credentials.");

            var accessToken = _tokenService.GenerateAccessToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshTokens.Add(refreshToken);
            await _db.SaveChangesAsync();

            var response = new AuthResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken.Token,
                Username = user.Username,
                Role = user.Role
            };

            return Ok(response);
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken))
                return BadRequest("Refresh token is required.");

            var storedToken = await _db.RefreshTokens
                .Include(rt => rt.User)
                .SingleOrDefaultAsync(rt => rt.Token == refreshToken);

            if (storedToken == null || !storedToken.IsActive)
                return Unauthorized("Invalid or expired refresh token.");

            // Revoke old refresh token (optional)
            storedToken.Revoked = System.DateTime.UtcNow;

            var newRefreshToken = _tokenService.GenerateRefreshToken();
            storedToken.User.RefreshTokens.Add(newRefreshToken);

            await _db.SaveChangesAsync();

            var newAccessToken = _tokenService.GenerateAccessToken(storedToken.User);

            return Ok(new AuthResponse
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken.Token,
                Username = storedToken.User.Username,
                Role = storedToken.User.Role
            });
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken)) return BadRequest();

            var token = await _db.RefreshTokens.SingleOrDefaultAsync(t => t.Token == refreshToken);
            if (token == null) return NotFound();

            token.Revoked = System.DateTime.UtcNow;
            await _db.SaveChangesAsync();
            return Ok(new { message = "Logged out" });
        }

        [Authorize]
        [HttpGet("me")]
        public async Task<IActionResult> Me()
        {
            var username = User.Identity?.Name;
            if (string.IsNullOrWhiteSpace(username)) return Unauthorized();

            var user = await _db.Users
                        .Where(u => u.Username == username)
                        .Select(u => new { u.Id, u.Username, u.Role })
                        .SingleOrDefaultAsync();

            return Ok(user);
        }
    }
}
