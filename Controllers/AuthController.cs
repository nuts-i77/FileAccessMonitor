using FileAccessMonitor.Data;
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
    private readonly LoginThrottle _throttle;

    public AuthController(UserManager<ApplicationUser> userManager, TokenService tokens, AuditLog audit, LoginThrottle throttle)
    {
        _userManager = userManager;
        _tokens = tokens;
        _audit = audit;
        _throttle = throttle;
    }

    // POST /api/auth/login
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest req)
    {
        var invalid = Unauthorized(new { error = Messages.Get("auth.invalid") });
        var lockedOut = StatusCode(StatusCodes.Status429TooManyRequests,
            new { error = Messages.Get("auth.lockedOut") });
        var name = req.Username ?? "";
        var address = HttpContext.Connection.RemoteIpAddress;

        // Too many failures from this address (or for this name): the password is not even checked
        if (_throttle.IsBlocked(name, address))
        {
            await _audit.WriteAsync(HttpContext, "auth.loginFailed", "reason=lockedOut", name);
            return lockedOut;
        }

        var user = await _userManager.FindByNameAsync(name);
        if (user == null || !await _userManager.CheckPasswordAsync(user, req.Password))
        {
            _throttle.Failed(name, address);
            var nowLocked = _throttle.IsBlocked(name, address);
            await _audit.WriteAsync(HttpContext, nowLocked ? "auth.lockedOut" : "auth.loginFailed",
                user == null ? "reason=unknownUser" : "reason=badPassword", user?.UserName ?? name);
            return nowLocked ? lockedOut : invalid;
        }
        _throttle.Succeeded(name, address);
        await _audit.WriteAsync(HttpContext, "auth.login", null, user.UserName);

        return Ok(new
        {
            token = await _tokens.CreateAsync(user),
            username = user.UserName,
            displayName = user.DisplayName,
            roles = await _userManager.GetRolesAsync(user)
        });
    }

    // POST /api/auth/logout  — ends this sign-in's token on the server (other sign-ins of the user stay)
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout([FromServices] AccessDbContext db)
    {
        await TokenService.RevokeAsync(User, db);
        await _audit.WriteAsync(HttpContext, "auth.logout");
        return Ok();
    }

    // GET /api/auth/me
    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> Me()
    {
        var user = await _userManager.FindByNameAsync(User.Identity!.Name!);
        if (user == null) return Unauthorized();
        var roles = await _userManager.GetRolesAsync(user);
        // Folders this user is limited to; allFolders = sees everything (Admins, and Viewers set to all folders), otherwise empty = nothing
        var folders = HttpContext.RequestServices.GetRequiredService<UserScopeService>().Get(User);
        var scope = (folders ?? []).Select(e => e.ToString());
        return Ok(new { username = user.UserName, displayName = user.DisplayName, roles, scopePaths = scope, allFolders = folders == null });
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
