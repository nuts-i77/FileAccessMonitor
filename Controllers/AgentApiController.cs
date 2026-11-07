using System.Text.Json;
using System.Text.Json.Nodes;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Controllers;

// Called by agents, on the agent HTTPS port only. Agents authenticate with the key they got at
// registration ("Authorization: Bearer <agent id>.<secret>"), not with a user sign-in.
[ApiController]
[Route("api/agent")]
[AllowAnonymous]
public class AgentApiController : ControllerBase
{
    internal const int MaxRecordsPerBatch = 5_000;

    private readonly AccessDbContext _db;
    private readonly AlertService _alerts;
    private readonly AuditLog _audit;
    private readonly IConfiguration _config;
    private readonly ILogger<AgentApiController> _logger;

    public AgentApiController(AccessDbContext db, AlertService alerts, AuditLog audit, IConfiguration config,
        ILogger<AgentApiController> logger)
    {
        _db = db;
        _alerts = alerts;
        _audit = audit;
        _config = config;
        _logger = logger;
    }

    private bool OnAgentPort => HttpContext.Connection.LocalPort == AgentEndpoint.Port(_config) && Request.IsHttps;

    // POST /api/agent/enroll  — exchanges a one-time registration code for the agent's own key
    [HttpPost("enroll")]
    public async Task<IActionResult> Enroll([FromBody] EnrollRequest req)
    {
        if (!OnAgentPort) return NotFound();
        var name = (req.Name ?? "").Trim();
        if (name.Length is 0 or > 255) return BadRequest(new { error = "name" });

        var codeHash = AgentSecrets.Hash(req.Code ?? "");
        var enrollment = await _db.AgentEnrollments.FindAsync(codeHash);
        if (enrollment == null || enrollment.ExpiresAt < DateTime.UtcNow)
        {
            await _audit.WriteAsync(HttpContext, "agent.enrollFailed", $"name={name}", "-");
            return Unauthorized(new { error = Messages.Get("agents.badCode") });
        }
        _db.AgentEnrollments.Remove(enrollment);

        // Registering a server again (reinstall) replaces its key; its records stay under the same name
        var agent = await _db.Agents.FirstOrDefaultAsync(a => a.Name.ToUpper() == name.ToUpper());
        if (agent == null)
            _db.Agents.Add(agent = new Agent { Id = Guid.NewGuid().ToString("N"), Name = name, CreatedAt = DateTime.UtcNow });
        var secret = AgentSecrets.NewSecret();
        agent.KeyHash = AgentSecrets.Hash(secret);
        agent.LastBatchSeq = 0; // a newly registered agent numbers its batches from 1 again
        agent.Disabled = false;
        agent.Version = req.Version;
        agent.LastSeenAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        await _audit.WriteAsync(HttpContext, "agent.enroll", $"name={name}", AuditLog.SystemUser);
        _logger.LogInformation("Agent {Name} registered.", name);
        return Ok(new EnrollResponse(agent.Id, $"{agent.Id}.{secret}"));
    }

    // POST /api/agent/batch  — records (or a gap report) from the agent's outbox
    [HttpPost("batch")]
    [RequestSizeLimit(64 * 1024 * 1024)]
    public async Task<IActionResult> Batch([FromBody] AgentBatch batch, [FromServices] DnsResolverService dns)
    {
        if (!OnAgentPort) return NotFound();
        if (await AuthenticateAsync() is not { } agent) return Unauthorized();
        if (batch.Records is { Count: > MaxRecordsPerBatch }) return BadRequest(new { error = "tooManyRecords" });

        agent.LastSeenAt = DateTime.UtcNow;
        // Batches waiting behind this one, so a backlog shows in the GUI while it is being sent
        if (int.TryParse(Request.Headers["X-Agent-Outbox"], out var waiting)) agent.OutboxCount = waiting;
        agent.OutboxFull = Request.Headers["X-Agent-Outbox-Full"] == "1";
        if (batch.Seq <= agent.LastBatchSeq)
        {
            await _db.SaveChangesAsync();
            return Ok(new { duplicate = true }); // already saved; the response was lost
        }

        var records = (batch.Records ?? []).Select(r => r.ToRecord(agent.Name)).ToList();
        // Agents send the client IP, and the machine name only when their logon events had it;
        // the rest is looked up here, with the one reverse-DNS setting of this server
        foreach (var byIp in records.Where(r => r.ClientIp != null && (r.ClientMachine == null || r.ClientMachine == r.ClientIp))
                     .GroupBy(r => r.ClientIp!))
        {
            if (dns.TryResolve(byIp.Key) is { } name)
                foreach (var r in byIp) r.ClientMachine = name;
        }
        _db.AccessRecords.AddRange(records);
        agent.LastBatchSeq = batch.Seq;
        await _db.SaveChangesAsync(); // records and sequence number in one transaction

        if (records.Count > 0) _alerts.Observe(records);
        if (batch.Gap is { } gap)
        {
            await _audit.WriteAsync(AuditLog.SystemUser, "collector.gap", gap.AuditDetail);
            object[] args = gap.Args.Select(a => long.TryParse(a, out var n) ? n : (object)a).ToArray();
            _ = Task.Run(() => _alerts.NotifyGapAsync(agent.Name, gap.MessageKey, args));
        }
        return Ok(new { saved = records.Count });
    }

    // POST /api/agent/heartbeat  — sent when there is nothing to send, so the GUI shows the agent is alive
    [HttpPost("heartbeat")]
    public async Task<IActionResult> Heartbeat([FromBody] HeartbeatRequest req)
    {
        if (!OnAgentPort) return NotFound();
        if (await AuthenticateAsync() is not { } agent) return Unauthorized();
        agent.LastSeenAt = DateTime.UtcNow;
        agent.Version = req.Version;
        if (req.OutboxCount is { } count) agent.OutboxCount = count;
        agent.OutboxFull = req.OutboxFull ?? false; // an older agent does not say: not full
        agent.OutboxBytes = req.OutboxBytes ?? 0;
        agent.AuditPolicyOk = req.AuditPolicyOk; // null: not known, or (Linux) no folders monitored yet
        if (req.Os is { Length: > 0 } os) agent.Os = os.Length <= 100 ? os : os[..100];
        await _db.SaveChangesAsync();
        return Ok(new { lastBatchSeq = agent.LastBatchSeq, configVersion = agent.ConfigVersion, protocol = AgentProtocol.Version });
    }

    // GET /api/agent/config  — monitored folders and recording rules for this agent's server
    [HttpGet("config")]
    public async Task<IActionResult> Config()
    {
        if (!OnAgentPort) return NotFound();
        if (await AuthenticateAsync() is not { } agent) return Unauthorized();
        var config = string.IsNullOrEmpty(agent.Config) ? new JsonObject() : JsonNode.Parse(agent.Config)!.AsObject();
        return Ok(new { version = agent.ConfigVersion, config });
    }

    // GET /api/agent/jobs  — long poll: waits up to 25 seconds for work from the GUI
    [HttpGet("jobs")]
    public async Task<IActionResult> NextJob([FromServices] AgentJobs jobs, [FromServices] IHostApplicationLifetime lifetime)
    {
        if (!OnAgentPort) return NotFound();
        if (await AuthenticateAsync() is not { } agent) return Unauthorized();
        // End the wait when the service stops, rather than holding up the shutdown
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(HttpContext.RequestAborted, lifetime.ApplicationStopping);
        try
        {
            var job = await jobs.NextAsync(agent.Id, TimeSpan.FromSeconds(25), stop.Token);
            return job == null ? NoContent() : Ok(job);
        }
        catch (OperationCanceledException)
        {
            return NoContent();
        }
    }

    // POST /api/agent/jobs/{id}  — the agent's answer to a job
    [HttpPost("jobs/{id}")]
    [RequestSizeLimit(256 * 1024 * 1024)] // a folder listing can be large
    public async Task<IActionResult> JobResult(string id, [FromBody] JsonObject result, [FromServices] AgentJobs jobs)
    {
        if (!OnAgentPort) return NotFound();
        if (await AuthenticateAsync() is not { } agent) return Unauthorized();
        return jobs.Complete(agent.Id, id, result) ? Ok() : NotFound(); // NotFound: the GUI request gave up
    }

    private async Task<Agent?> AuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.Ordinal)) return null;
        var parts = header["Bearer ".Length..].Split('.', 2);
        if (parts.Length != 2) return null;
        var agent = await _db.Agents.FindAsync(parts[0]);
        return agent != null && !agent.Disabled && AgentSecrets.Matches(parts[1], agent.KeyHash) ? agent : null;
    }
}
