using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace FileAccessMonitor.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")]
public class UsersController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly AccessDbContext _db;
    private readonly AlertService _alerts;
    private readonly AuditLog _audit;

    public UsersController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
        AccessDbContext db, AlertService alerts, AuditLog audit)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _db = db;
        _alerts = alerts;
        _audit = audit;
    }

    // GET /api/users
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var users = _userManager.Users.OrderBy(u => u.UserName).ToList();
        var scopes = _db.UserScopes.ToDictionary(s => s.UserId);
        var result = new List<object>();
        foreach (var u in users)
        {
            var roles = await _userManager.GetRolesAsync(u);
            scopes.TryGetValue(u.Id, out var scope);
            result.Add(new
            {
                id = u.Id, username = u.UserName, displayName = u.DisplayName, email = u.Email, roles,
                scopePaths = AccessScope.ParsePaths(scope?.Paths), notifyEmail = scope?.NotifyEmail,
            });
        }
        return Ok(result);
    }

    // POST /api/users
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateUserRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
            return BadRequest(new { error = Messages.Get("user.bothRequired") });

        var user = new ApplicationUser
        {
            UserName = req.Username,
            DisplayName = string.IsNullOrWhiteSpace(req.DisplayName) ? req.Username : req.DisplayName,
            Email = string.IsNullOrWhiteSpace(req.Email) ? $"{req.Username}@localhost" : req.Email
        };
        var result = await _userManager.CreateAsync(user, req.Password);
        if (!result.Succeeded)
            return BadRequest(new { error = Messages.Join(result) });

        var role = req.Role is "Admin" or "Viewer" ? req.Role : "Viewer";
        if (await _roleManager.RoleExistsAsync(role))
            await _userManager.AddToRoleAsync(user, role);

        await _audit.WriteAsync(HttpContext, "user.create", $"user={user.UserName}, role={role}");
        return Ok(new { message = Messages.Get("user.created", user.UserName), id = user.Id });
    }

    // DELETE /api/users/{id}
    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(string id)
    {
        var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (id == currentUserId)
            return BadRequest(new { error = Messages.Get("user.cannotDeleteSelf") });

        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound(new { error = Messages.Get("user.notFound") });

        var result = await _userManager.DeleteAsync(user);
        if (!result.Succeeded)
            return BadRequest(new { error = Messages.Join(result) });
        if (await _db.UserScopes.FindAsync(id) is { } deletedScope)
        {
            _db.UserScopes.Remove(deletedScope);
            await _db.SaveChangesAsync();
            _alerts.ReloadRecipients();
        }

        await _audit.WriteAsync(HttpContext, "user.delete", $"user={user.UserName}");
        return Ok(new { message = Messages.Get("user.deleted", user.UserName) });
    }

    // PUT /api/users/{id}/scope  — folders a Viewer may see, and where to mail alerts about them
    [HttpPut("{id}/scope")]
    public async Task<IActionResult> SetScope(string id, [FromBody] ScopeRequest req)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound(new { error = Messages.Get("user.notFound") });

        var paths = AccessScope.ParsePaths(string.Join('\n', req.Paths ?? []));
        var (configs, _) = SettingsController.ReadSettingsDoc();
        if (paths.FirstOrDefault(p => !configs.Any(c => EventLogCollectorService.IsUnderPath(p, c.Path))) is { } outside)
            return BadRequest(new { error = Messages.Get("scope.notMonitored", outside) });

        var email = string.IsNullOrWhiteSpace(req.NotifyEmail) ? null : req.NotifyEmail.Trim();
        if (email != null && !System.Net.Mail.MailAddress.TryCreate(email, out _))
            return BadRequest(new { error = Messages.Get("scope.invalidEmail") });
        if (email != null && paths.Count == 0)
            return BadRequest(new { error = Messages.Get("scope.emailNeedsPaths") });

        var row = await _db.UserScopes.FindAsync(id);
        if (paths.Count == 0)
        {
            if (row != null) _db.UserScopes.Remove(row);
        }
        else
        {
            if (row == null) _db.UserScopes.Add(row = new UserScope { UserId = id });
            row.Paths = string.Join('\n', paths);
            row.NotifyEmail = email;
        }
        await _db.SaveChangesAsync();
        _alerts.ReloadRecipients();

        await _audit.WriteAsync(HttpContext, "user.scope",
            $"user={user.UserName}, paths=[{string.Join(", ", paths)}], notifyEmail={email ?? "-"}");
        return Ok(new { message = Messages.Get("scope.saved") });
    }

    // PUT /api/users/{id}/role
    [HttpPut("{id}/role")]
    public async Task<IActionResult> ChangeRole(string id, [FromBody] ChangeRoleRequest req)
    {
        var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (id == currentUserId)
            return BadRequest(new { error = Messages.Get("user.cannotChangeOwnRole") });

        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound(new { error = Messages.Get("user.notFound") });

        if (req.Role is not ("Admin" or "Viewer"))
            return BadRequest(new { error = Messages.Get("user.invalidRole") });

        var currentRoles = await _userManager.GetRolesAsync(user);
        await _userManager.RemoveFromRolesAsync(user, currentRoles);
        await _userManager.AddToRoleAsync(user, req.Role);
        // Invalidate the user's existing tokens so the new role applies right away
        await _userManager.UpdateSecurityStampAsync(user);
        await _audit.WriteAsync(HttpContext, "user.role", $"user={user.UserName}, role={req.Role}");

        return Ok(new { message = Messages.Get("user.roleChanged") });
    }

    // POST /api/users/{id}/reset-password
    [HttpPost("{id}/reset-password")]
    public async Task<IActionResult> ResetPassword(string id, [FromBody] ResetPasswordRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.NewPassword))
            return BadRequest(new { error = Messages.Get("password.required") });

        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound(new { error = Messages.Get("user.notFound") });

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var result = await _userManager.ResetPasswordAsync(user, token, req.NewPassword);
        if (!result.Succeeded)
            return BadRequest(new { error = Messages.Join(result) });

        await _audit.WriteAsync(HttpContext, "user.resetPassword", $"user={user.UserName}");
        return Ok(new { message = Messages.Get("password.reset") });
    }
}

public record CreateUserRequest(string Username, string? DisplayName, string? Email, string? Password, string? Role);
public record ChangeRoleRequest(string Role);
public record ResetPasswordRequest(string NewPassword);
public record ScopeRequest(string[]? Paths, string? NotifyEmail);
