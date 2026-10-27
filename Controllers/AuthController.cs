using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace FileAccessMonitor.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly TokenService _tokens;
    private readonly AuditLog _audit;

    public AuthController(UserManager<ApplicationUser> userManager, TokenService tokens, AuditLog audit)
    {
        _userManager = userManager;
        _tokens = tokens;
        _audit = audit;
    }

    // POST /api/auth/login
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest req)
    {
        var invalid = Unauthorized(new { error = Messages.Get("auth.invalid") });
        var lockedOut = StatusCode(StatusCodes.Status429TooManyRequests,
            new { error = Messages.Get("auth.lockedOut") });

        var user = await _userManager.FindByNameAsync(req.Username);
        if (user == null)
        {
            await _audit.WriteAsync(HttpContext, "auth.loginFailed", "reason=unknownUser", req.Username);
            return invalid;
        }
        if (await _userManager.IsLockedOutAsync(user))
        {
            await _audit.WriteAsync(HttpContext, "auth.loginFailed", "reason=lockedOut", user.UserName);
            return lockedOut;
        }

        if (!await _userManager.CheckPasswordAsync(user, req.Password))
        {
            await _userManager.AccessFailedAsync(user);
            var nowLocked = await _userManager.IsLockedOutAsync(user);
            await _audit.WriteAsync(HttpContext, nowLocked ? "auth.lockedOut" : "auth.loginFailed",
                "reason=badPassword", user.UserName);
            return nowLocked ? lockedOut : invalid;
        }
        await _userManager.ResetAccessFailedCountAsync(user);
        await _audit.WriteAsync(HttpContext, "auth.login", null, user.UserName);

        return Ok(new
        {
            token = await _tokens.CreateAsync(user),
            username = user.UserName,
            displayName = user.DisplayName,
            roles = await _userManager.GetRolesAsync(user)
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
        await _audit.WriteAsync(HttpContext, "password.change");
        // The security stamp changed, so the caller needs a new token to stay signed in.
        return Ok(new { message = Messages.Get("password.changed"), token = await _tokens.CreateAsync(user) });
    }
}

public record LoginRequest(string Username, string Password);
public record ChangePasswordRequest(string CurrentPassword, string NewPassword);
