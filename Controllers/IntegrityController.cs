using System.Text;
using System.Text.Json;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FileAccessMonitor.Controllers;

// Tamper detection of the records: status, verification, accepting a finding, anchors
[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")]
public class IntegrityController : ControllerBase
{
    private readonly IntegrityService _integrity;
    private readonly AuditLog _audit;

    public IntegrityController(IntegrityService integrity, AuditLog audit)
    {
        _integrity = integrity;
        _audit = audit;
    }

    // GET /api/integrity/status
    [HttpGet("status")]
    public async Task<IActionResult> Status(CancellationToken ct) => Ok(await _integrity.GetStatusAsync(ct));

    // POST /api/integrity/verify: starts a full verification (the one already running is returned)
    [HttpPost("verify")]
    public IActionResult Verify()
    {
        var run = _integrity.StartVerify(User.Identity?.Name ?? AuditLog.SystemUser);
        return Accepted(new { id = run.Id });
    }

    // GET /api/integrity/verify/{id}
    [HttpGet("verify/{id}")]
    public IActionResult Progress(string id) =>
        _integrity.GetRun(id) is { } run ? Ok(run) : NotFound(new { error = Messages.Get("integrity.runNotFound") });

    // POST /api/integrity/accept
    [HttpPost("accept")]
    public async Task<IActionResult> Accept([FromBody] AcceptBreakRequest req, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Chain))
            return BadRequest(new { error = Messages.Get("integrity.nothingToAccept") });
        var accepted = await _integrity.AcceptAsync(req.Chain, req.BreakId, req.Note?.Trim(), User.Identity?.Name ?? "", ct);
        if (accepted == null)
            return BadRequest(new { error = Messages.Get("integrity.nothingToAccept") });
        return Ok(new { message = Messages.Get("integrity.accepted", accepted) });
    }

    // GET /api/integrity/anchor: the heads of both chains as a signed file to keep somewhere else
    [HttpGet("anchor")]
    public async Task<IActionResult> Anchor(CancellationToken ct)
    {
        var a = await _integrity.CreateAnchorAsync(ct);
        if (a == null) return BadRequest(new { error = Messages.Get("integrity.noKey") });
        await _audit.WriteAsync(HttpContext, "integrity.anchor", $"download, access seq={a.AccessSeq}, audit seq={a.AuditSeq}");

        var json = JsonSerializer.Serialize(new
        {
            format = "fam-anchor-v1", line = a.Line, server = a.Server, time = a.Time, keyId = a.KeyId,
            access = new { seq = a.AccessSeq, hash = a.AccessHash }, audit = new { seq = a.AuditSeq, hash = a.AuditHash },
            mac = a.Mac,
        }, new JsonSerializerOptions { WriteIndented = true });
        return File(Encoding.UTF8.GetBytes(json), "application/json", $"fam-anchor-{a.Server}-{a.Time:yyyyMMdd-HHmm}.json");
    }

    // POST /api/integrity/check-anchor
    [HttpPost("check-anchor")]
    public async Task<IActionResult> CheckAnchor([FromBody] CheckAnchorRequest req, CancellationToken ct)
    {
        var result = string.IsNullOrWhiteSpace(req.Text) || req.Text.Length > 20000 ? null : await _integrity.CheckAnchorAsync(req.Text, ct);
        return result == null ? BadRequest(new { error = Messages.Get("integrity.anchorInvalid") }) : Ok(result);
    }
}

public record AcceptBreakRequest(string? Chain, string? BreakId, string? Note);

public record CheckAnchorRequest(string? Text);
