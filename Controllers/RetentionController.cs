using FileAccessMonitor.Data;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class RetentionController : ControllerBase
{
    private readonly AccessDbContext _db;
    private readonly RetentionService _retention;
    private readonly UserScopeService _scopes;
    private readonly AuditLog _audit;

    public RetentionController(AccessDbContext db, RetentionService retention, UserScopeService scopes, AuditLog audit)
    {
        _db = db;
        _scopes = scopes;
        _retention = retention;
        _audit = audit;
    }

    // GET /api/retention
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var days = RetentionService.GetRetentionDays();
        var records = _scopes.Records(User); // counts within the user's scope
        var total = await records.CountAsync();
        var oldest = total > 0 ? await records.MinAsync(r => (DateTime?)r.AccessTime) : null;

        int toDelete = 0;
        if (days > 0)
        {
            var cutoff = DateTime.UtcNow.AddDays(-days);
            toDelete = await records.CountAsync(r => r.AccessTime < cutoff);
        }

        return Ok(new { retentionDays = days, totalRecords = total, oldestRecord = oldest, recordsToDelete = toDelete });
    }

    // PUT /api/retention  (Admin only)
    [HttpPut]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> Set([FromBody] SetRetentionRequest req)
    {
        if (req.RetentionDays < 0)
            return BadRequest(new { error = Messages.Get("retention.invalidDays") });

        RetentionService.SaveRetentionDays(req.RetentionDays);
        await _audit.WriteAsync(HttpContext, "retention.update", $"days={req.RetentionDays}");

        var label = req.RetentionDays == 0 ? Messages.Get("retention.forever") : Messages.Get("retention.days", req.RetentionDays);
        return Ok(new { message = Messages.Get("retention.updated", label), retentionDays = req.RetentionDays });
    }

    // POST /api/retention/cleanup  (Admin only)
    [HttpPost("cleanup")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> Cleanup()
    {
        var days = RetentionService.GetRetentionDays();
        if (days <= 0)
            return BadRequest(new { error = Messages.Get("retention.notSet") });

        var deleted = await _retention.RunCleanup();
        await _audit.WriteAsync(HttpContext, "retention.cleanup", $"days={days}, deleted={deleted}");
        return Ok(new { message = Messages.Get("retention.deleted", deleted), deletedCount = deleted });
    }
}

public record SetRetentionRequest(int RetentionDays);
