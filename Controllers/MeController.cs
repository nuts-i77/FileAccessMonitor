using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace FileAccessMonitor.Controllers;

[ApiController]
[Route("api/me")]
[Authorize]
public class MeController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;

    public MeController(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    // POST /api/me/change-password  (all authenticated users)
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangeOwnPasswordRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.CurrentPassword) || string.IsNullOrWhiteSpace(req.NewPassword))
            return BadRequest(new { error = Messages.Get("password.bothRequired") });

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = await _userManager.FindByIdAsync(userId ?? "");
        if (user == null) return Unauthorized();

        var result = await _userManager.ChangePasswordAsync(user, req.CurrentPassword, req.NewPassword);
        if (!result.Succeeded)
            return BadRequest(new { error = Messages.Join(result) });

        if (user.UserName == "admin") SecretStore.DeleteInitialAdminPassword();
        return Ok(new { message = Messages.Get("password.changed") });
    }
}

public record ChangeOwnPasswordRequest(string CurrentPassword, string NewPassword);
