using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using FileAccessMonitor.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace FileAccessMonitor.Services;

public class TokenService(IConfiguration config, UserManager<ApplicationUser> userManager)
{
    // Carries the user's Identity security stamp. Deleting the user, changing roles or
    // passwords changes the stamp, so tokens issued before that stop working immediately.
    public const string SecurityStampClaim = "sstamp";

    public async Task<string> CreateAsync(ApplicationUser user)
    {
        var roles = await userManager.GetRolesAsync(user);
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expires = DateTime.UtcNow.AddHours(config.GetValue("Jwt:ExpiresHours", 24));

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, user.UserName!),
            new(ClaimTypes.NameIdentifier, user.Id),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(SecurityStampClaim, await userManager.GetSecurityStampAsync(user)),
        };
        foreach (var role in roles)
            claims.Add(new Claim(ClaimTypes.Role, role));

        var token = new JwtSecurityToken(
            issuer: config["Jwt:Issuer"],
            audience: config["Jwt:Audience"],
            claims: claims,
            expires: expires,
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    // Called for every authenticated request (JwtBearerEvents.OnTokenValidated).
    public static async Task<bool> IsCurrentAsync(ClaimsPrincipal principal, UserManager<ApplicationUser> userManager)
    {
        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        var stamp = principal.FindFirstValue(SecurityStampClaim);
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(stamp)) return false;

        var user = await userManager.FindByIdAsync(userId);
        return user != null && stamp == await userManager.GetSecurityStampAsync(user);
    }
}
