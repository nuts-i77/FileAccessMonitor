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
// The local collector (the privileged process of this server, see LocalCollector) calls the same API over
// loopback with its own credential "local.<secret>" and is handled as an agent named like this server.
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
    private readonly LocalCollectorState _collector;

    public AgentApiController(AccessDbContext db, AlertService alerts, AuditLog audit, IConfiguration config,
        ILogger<AgentApiController> logger, LocalCollectorState collector)
    {
        _collector = collector;
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
        // Registering a server again (reinstall) replaces its key; its records stay under the same name.
        // Only a code issued for that agent can do it, so a code for a new server cannot take over another
        // one, and nothing can register under this server's own name. A refused code stays usable.
        var agent = await _db.Agents.FirstOrDefaultAsync(a => a.Name.ToUpper() == name.ToUpper());
        if (EnrollRefusal(name, agent, enrollment) is { } refusal)
        {
            await _audit.WriteAsync(HttpContext, "agent.enrollFailed", $"name={name} reason={refusal.Reason}", "-");
            return Conflict(new { error = refusal.Message });
        }
        _db.AgentEnrollments.Remove(enrollment);

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

        var isLocal = IsLocalCollector(agent);
        agent.LastSeenAt = DateTime.UtcNow;
        if (isLocal)
        {
            _collector.Touch(agent.LastSeenAt.Value);
            agent.LastBatchSeq = await LoadLocalSeqAsync();
        }
        // Batches waiting behind this one, so a backlog shows in the GUI while it is being sent
        if (int.TryParse(Request.Headers["X-Agent-Outbox"], out var waiting))
        {
            agent.OutboxCount = waiting;
        }
        agent.OutboxFull = Request.Headers["X-Agent-Outbox-Full"] == "1";
        if (isLocal) _collector.SetOutbox(agent.OutboxCount, agent.OutboxFull);
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
        if (isLocal) await StoreLocalSeqAsync(batch.Seq);
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
        if (IsLocalCollector(agent))
        {
            _collector.Heartbeat(req, DateTime.UtcNow);
            var local = LocalCollector.ConfigFrom(LocalSettings());
            return Ok(new { lastBatchSeq = await LoadLocalSeqAsync(), configVersion = LocalCollector.ConfigVersion(local), protocol = AgentProtocol.Version });
        }
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
        if (IsLocalCollector(agent))
        {
            // This machine's own settings. "position": where the collector inside the web service got to before
            // the collector became a separate process (1.10 and older); a collector that has no position of its
            // own continues there. Not offered once batches of the new collector have been saved.
            var local = LocalCollector.ConfigFrom(LocalSettings());
            var position = await _db.CollectorStates.AsNoTracking().AnyAsync(s => s.Key == LocalCollector.SeqStateKey)
                ? ""
                : (await _db.CollectorStates.AsNoTracking().FirstOrDefaultAsync(s => s.Key == LocalPositionKey))?.Value ?? "";
            return Ok(new { version = LocalCollector.ConfigVersion(local), config = local, position });
        }
        var config = string.IsNullOrEmpty(agent.Config) ? new JsonObject() : JsonNode.Parse(agent.Config)!.AsObject();
        return Ok(new { version = agent.ConfigVersion, config });
    }

    // GET /api/agent/jobs  — long poll: waits up to 25 seconds for work from the GUI
    [HttpGet("jobs")]
    public async Task<IActionResult> NextJob([FromServices] AgentJobs jobs, [FromServices] IHostApplicationLifetime lifetime)
    {
        if (!OnAgentPort) return NotFound();
        if (await AuthenticateAsync() is not { } agent) return Unauthorized();
        if (IsLocalCollector(agent)) _collector.Touch(DateTime.UtcNow); // it asks every 25 seconds
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
        if (parts[0] == LocalCollector.AgentId)
        {
            // The local collector: only from this machine, and only while this server collects
            var loopback = HttpContext.Connection.RemoteIpAddress is { } ip && System.Net.IPAddress.IsLoopback(ip);
            return loopback && ServerConfigService.LocalCollects && LocalCollector.Matches(parts[1], LocalFolder)
                ? LocalCollector.PseudoAgent() : null;
        }
        var agent = await _db.Agents.FindAsync(parts[0]);
        return agent != null && !agent.Disabled && AgentSecrets.Matches(parts[1], agent.KeyHash) ? agent : null;
    }

    // Where the collector's key.hash is looked for (the tests point it at a temporary folder)
    internal static string? LocalFolder { get; set; }

    // This machine's settings.json (the tests replace it)
    internal static Func<JsonObject> LocalSettings { get; set; } = SettingsStore.Load;

    private static bool IsLocalCollector(Agent agent) => agent.Id == LocalCollector.AgentId;

    private (string Reason, string Message)? EnrollRefusal(string name, Agent? existing, AgentEnrollment code)
    {
        if (ServerConfigService.IsLocal(name))
            return ("serverName", Messages.Get("agents.nameIsServer", name));
        if (code.AgentId != null && existing?.Id != code.AgentId)
        {
            var target = _db.Agents.Find(code.AgentId);
            return ("codeForOther", target == null ? Messages.Get("agents.badCode") : Messages.Get("agents.codeForOther", target.Name));
        }
        if (existing != null && code.AgentId == null)
            return ("nameTaken", Messages.Get("agents.nameTaken", existing.Name));
        return null;
    }

    // The position the server's own collector saved in the database before it became a separate process
    private const string LocalPositionKey = "LastRecordId";

    // The batch sequence saved from the collector, valid for the key it was saved with (a collector that
    // started over with a new key numbers its batches from 1 again)
    private async Task<long> LoadLocalSeqAsync()
    {
        var row = await _db.CollectorStates.AsNoTracking().FirstOrDefaultAsync(s => s.Key == LocalCollector.SeqStateKey);
        var hash = LocalCollector.ReadKeyHash(LocalFolder);
        var parts = row?.Value.Split(':', 2);
        return parts is { Length: 2 } && hash != null && parts[0] == hash && long.TryParse(parts[1], out var seq) ? seq : 0;
    }

    private async Task StoreLocalSeqAsync(long seq)
    {
        var value = $"{LocalCollector.ReadKeyHash(LocalFolder)}:{seq}";
        var row = await _db.CollectorStates.FindAsync(LocalCollector.SeqStateKey);
        if (row == null) _db.CollectorStates.Add(new CollectorState { Key = LocalCollector.SeqStateKey, Value = value });
        else row.Value = value;
    }
}
