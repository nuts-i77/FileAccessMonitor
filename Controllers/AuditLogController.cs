using FileAccessMonitor.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Controllers;

[ApiController]
[Route("api/auditlog")]
[Authorize(Roles = "Admin")]
public class AuditLogController : ControllerBase
{
    private readonly AccessDbContext _db;

    public AuditLogController(AccessDbContext db)
    {
        _db = db;
    }

    // GET /api/auditlog?page=1&pageSize=50
    [HttpGet]
    public async Task<IActionResult> Get([FromQuery] int page = 1, [FromQuery] int pageSize = 50)
    {
        if (pageSize < 1 || pageSize > 500) pageSize = 50;
        if (page < 1) page = 1;

        var total = await _db.AuditLogs.CountAsync();
        var items = await _db.AuditLogs
            .OrderByDescending(e => e.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(e => new { e.Time, e.UserName, e.Action, e.Detail, e.ClientIp })
            .ToListAsync();

        return Ok(new { total, page, pageSize, items });
    }
}
