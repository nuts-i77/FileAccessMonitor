using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace FileAccessMonitor.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _config;

    public AuthController(UserManager<ApplicationUser> userManager, IConfiguration config)
    {
        _userManager = userManager;
        _config = config;
    }

    // POST /api/auth/login
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest req)
    {
        var invalid = Unauthorized(new { error = Messages.Get("auth.invalid") });
        var lockedOut = StatusCode(StatusCodes.Status429TooManyRequests,
            new { error = Messages.Get("auth.lockedOut") });

        var user = await _userManager.FindByNameAsync(req.Username);
        if (user == null) return invalid;
        if (await _userManager.IsLockedOutAsync(user)) return lockedOut;

        if (!await _userManager.CheckPasswordAsync(user, req.Password))
        {
            await _userManager.AccessFailedAsync(user);
            return await _userManager.IsLockedOutAsync(user) ? lockedOut : invalid;
        }
        await _userManager.ResetAccessFailedCountAsync(user);

        var roles = await _userManager.GetRolesAsync(user);
        var token = GenerateToken(user, roles);

        return Ok(new
        {
            token,
            username = user.UserName,
            displayName = user.DisplayName,
            roles
        });
    }

    // GET /api/auth/me
    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> Me()
    {
        var user = await _userManager.FindByNameAsync(User.Identity!.Name!);
        if (user == null) return Unauthorized();
        var roles = await _userManager.GetRolesAsync(user);
        return Ok(new { username = user.UserName, displayName = user.DisplayName, roles });
    }

    // POST /api/auth/change-password
    [HttpPost("change-password")]
    [Authorize]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest req)
    {
        var user = await _userManager.FindByNameAsync(User.Identity!.Name!);
        if (user == null) return Unauthorized();

        var result = await _userManager.ChangePasswordAsync(user, req.CurrentPassword, req.NewPassword);
        if (!result.Succeeded)
            return BadRequest(new { error = Messages.Join(result) });

        if (user.UserName == "admin") SecretStore.DeleteInitialAdminPassword();
        return Ok(new { message = Messages.Get("password.changed") });
    }

    private string GenerateToken(ApplicationUser user, IList<string> roles)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expires = DateTime.UtcNow.AddHours(
            _config.GetValue("Jwt:ExpiresHours", 24));

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, user.UserName!),
            new(ClaimTypes.NameIdentifier, user.Id),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
        foreach (var role in roles)
            claims.Add(new Claim(ClaimTypes.Role, role));

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: expires,
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

public record LoginRequest(string Username, string Password);
public record ChangePasswordRequest(string CurrentPassword, string NewPassword);
