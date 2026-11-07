using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Controllers;

// Admin management of agents: list them, issue registration codes, disable or remove them.
[ApiController]
[Route("api/agents")]
[Authorize(Roles = "Admin")]
public class AgentsController : ControllerBase
{
    internal static readonly TimeSpan CodeLifetime = TimeSpan.FromHours(24);

    private readonly AccessDbContext _db;
    private readonly AuditLog _audit;
    private readonly IConfiguration _config;
    private readonly LocalCollectorState _collector;

    public AgentsController(AccessDbContext db, AuditLog audit, IConfiguration config, LocalCollectorState collector)
    {
        _collector = collector;
        _db = db;
        _audit = audit;
        _config = config;
    }

    // GET /api/agents
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var agents = await _db.Agents.OrderBy(a => a.Name).ToListAsync();
        return Ok(new
        {
            // The agent port opens at startup unless turned off in settings.json
            featureOn = AgentEndpoint.Active,
            endpointReady = AgentEndpoint.Certificate != null,
            port = AgentEndpoint.Port(_config),
            serverVersion = SettingsController.AppVersion,
            // This machine's own collector service (not an agent: it is not in the list below)
            local = ServerConfigService.LocalCollects
                ? new { name = ServerConfigService.LocalName, status = CollectorStatus.From(_collector) }
                : null,
            agents = agents.Select(a => new { a.Id, a.Name, a.CreatedAt, a.LastSeenAt, a.Version, a.Disabled, a.OutboxCount, a.AuditPolicyOk, a.Os, a.OutboxFull, a.OutboxBytes }),
        });
    }

    // POST /api/agents/enrollment  — a one-time registration code, valid for 24 hours
    [HttpPost("enrollment")]
    public async Task<IActionResult> CreateEnrollment()
    {
        if (!AgentEndpoint.Active)
            return Conflict(new { error = Messages.Get("agents.portOff") });
        if (AgentEndpoint.Certificate is not { } cert)
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = Messages.Get("agents.noEndpoint") });

        await _db.AgentEnrollments.Where(e => e.ExpiresAt < DateTime.UtcNow).ExecuteDeleteAsync();
        var code = AgentSecrets.NewSecret();
        var expiresAt = DateTime.UtcNow.Add(CodeLifetime);
        _db.AgentEnrollments.Add(new AgentEnrollment { CodeHash = AgentSecrets.Hash(code), ExpiresAt = expiresAt });
        await _db.SaveChangesAsync();

        // The host name the Admin reached the GUI with is usually reachable from file servers too;
        // it can be edited in the GUI before copying
        var host = Request.Host.Host;
        var url = $"https://{(host.Contains(':') ? $"[{host}]" : host)}:{AgentEndpoint.Port(_config)}";
        await _audit.WriteAsync(HttpContext, "agent.code", $"expiresAt={expiresAt:O}");
        return Ok(new
        {
            url, fingerprint = AgentSecrets.Fingerprint(cert), code, expiresAt,
            connection = new AgentConnection(url, AgentSecrets.Fingerprint(cert), code).ToString(),
        });
    }

    // POST /api/agents/connection  — rebuilds the connection string with another server address
    [HttpPost("connection")]
    public IActionResult Connection([FromBody] ConnectionRequest req)
    {
        if (!Uri.TryCreate(req.Url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            return BadRequest(new { error = Messages.Get("agents.badUrl") });
        return Ok(new { connection = new AgentConnection(uri.GetLeftPart(UriPartial.Authority), req.Fingerprint, req.Code).ToString() });
    }

    // PUT /api/agents/{id}/disabled
    [HttpPut("{id}/disabled")]
    public async Task<IActionResult> SetDisabled(string id, [FromBody] DisableRequest req)
    {
        var agent = await _db.Agents.FindAsync(id);
        if (agent == null) return NotFound(new { error = Messages.Get("agents.notFound") });
        agent.Disabled = req.Disabled;
        await _db.SaveChangesAsync();
        await _audit.WriteAsync(HttpContext, req.Disabled ? "agent.disable" : "agent.enable", $"name={agent.Name}");
        return Ok(new { message = Messages.Get(req.Disabled ? "agents.disabled" : "agents.enabled", agent.Name) });
    }

    // DELETE /api/agents/{id}  — its records stay; the agent has to be registered again to send more
    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(string id)
    {
        var agent = await _db.Agents.FindAsync(id);
        if (agent == null) return NotFound(new { error = Messages.Get("agents.notFound") });
        _db.Agents.Remove(agent);
        await _db.SaveChangesAsync();
        await _audit.WriteAsync(HttpContext, "agent.delete", $"name={agent.Name}");
        return Ok(new { message = Messages.Get("agents.deleted", agent.Name) });
    }
}

public record ConnectionRequest(string Url, string Fingerprint, string Code);
public record DisableRequest(bool Disabled);
