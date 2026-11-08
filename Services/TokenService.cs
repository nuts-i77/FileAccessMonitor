using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace FileAccessMonitor.Services;

public class TokenService(IConfiguration config, UserManager<ApplicationUser> userManager)
{
    // Carries the user's Identity security stamp. Deleting the user, changing roles or
    // passwords changes the stamp, so tokens issued before that stop working immediately.
    public const string SecurityStampClaim = "sstamp";

    internal const int DefaultExpiresHours = 8;

    public async Task<string> CreateAsync(ApplicationUser user)
    {
        var roles = await userManager.GetRolesAsync(user);
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expires = DateTime.UtcNow.AddHours(config.GetValue("Jwt:ExpiresHours", DefaultExpiresHours));

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
    public static async Task<bool> IsCurrentAsync(ClaimsPrincipal principal, UserManager<ApplicationUser> userManager, AccessDbContext db)
    {
        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        var stamp = principal.FindFirstValue(SecurityStampClaim);
        var jti = principal.FindFirstValue(JwtRegisteredClaimNames.Jti);
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(stamp) || string.IsNullOrEmpty(jti)) return false;

        var user = await userManager.FindByIdAsync(userId);
        if (user == null || stamp != await userManager.GetSecurityStampAsync(user)) return false;
        return !await db.RevokedTokens.AnyAsync(t => t.Jti == jti);   // signed out
    }

    // Signing out ends this token only (the user's other sign-ins stay); kept until the token would expire
    public static async Task RevokeAsync(ClaimsPrincipal principal, AccessDbContext db)
    {
        var jti = principal.FindFirstValue(JwtRegisteredClaimNames.Jti);
        if (string.IsNullOrEmpty(jti)) return;
        var expiresAt = long.TryParse(principal.FindFirstValue(JwtRegisteredClaimNames.Exp), out var exp)
            ? DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime
            : DateTime.UtcNow.AddDays(30);
        var now = DateTime.UtcNow;
        await db.RevokedTokens.Where(t => t.ExpiresAt < now).ExecuteDeleteAsync();
        if (!await db.RevokedTokens.AnyAsync(t => t.Jti == jti))
        {
            db.RevokedTokens.Add(new RevokedToken { Jti = jti, ExpiresAt = expiresAt });
            await db.SaveChangesAsync();
        }
    }
}
