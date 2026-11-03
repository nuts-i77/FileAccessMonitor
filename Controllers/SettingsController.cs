using System.Text.Json.Nodes;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Mvc;

namespace FileAccessMonitor.Controllers;

// Monitored folders and recording rules are per file server (?server= / "server" in the body;
// empty = this machine). On an agent's server, checking a folder and setting its SACL are done by
// the agent, as a job it picks up.
[ApiController]
[Route("api/[controller]")]
[Microsoft.AspNetCore.Authorization.Authorize(Roles = "Admin")]
public class SettingsController : ControllerBase
{
    private static readonly string[] DefaultEventTypes = ["Read", "Write", "Delete"];
    // Setting a SACL walks every file below the folder, which can take minutes on a large share
    private static readonly TimeSpan SaclJobTimeout = TimeSpan.FromMinutes(15);

    // Sets up auditing on this machine (SACLs on Windows, Samba on Linux), the same way an agent
    // does on its server; null when this machine does not collect
    private readonly IAgentPlatform? _local;
    private readonly DnsResolverService _dns;
    private readonly ServerConfigService _servers;
    private readonly AgentJobs _jobs;
    private readonly AuditLog _audit;
    private readonly ILogger<SettingsController> _logger;

    public SettingsController(IServiceProvider services, DnsResolverService dns, ServerConfigService servers,
        AgentJobs jobs, AuditLog audit, ILogger<SettingsController> logger)
    {
        _local = services.GetService<IAgentPlatform>();
        _dns = dns;
        _servers = servers;
        _jobs = jobs;
        _audit = audit;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> Get([FromQuery] string? server = null)
    {
        var (_, dns) = ReadSettingsDoc();
        // A monitoring-only server has no folders of its own, but the global settings still apply
        if (ServerConfigService.IsLocal(server) && !ServerConfigService.LocalCollects)
            return Ok(new { pathConfigs = Array.Empty<PathConfig>(), dnsServer = dns });
        if (await CheckServerAsync(server) is { } error) return error;
        return Ok(new { pathConfigs = await _servers.GetPathsAsync(server), dnsServer = dns });
    }

    // GET /api/settings/servers  — this machine (when it collects) and the agents, for the server pickers
    [HttpGet("servers")]
    public async Task<IActionResult> Servers() => Ok(new
    {
        local = ServerConfigService.LocalCollects ? ServerConfigService.LocalName : null,
        servers = await _servers.ServerNamesAsync(),
    });

    [HttpPost("dns")]
    public async Task<IActionResult> SetDns([FromBody] DnsRequest req)
    {
        var server = req.DnsServer?.Trim() ?? "";
        _dns.SetDnsServer(server);
        SettingsStore.Update(root => root["DnsServer"] = server);
        _logger.LogInformation("DNS server updated: {Dns}", server);
        await _audit.WriteAsync(HttpContext, "dns.update", $"dnsServer={server}");
        return Ok(new { dnsServer = server });
    }

    // GET /api/settings/app  — running version, and whether Admins' browsers check GitHub for updates
    [HttpGet("app")]
    public IActionResult GetApp() => Ok(new
    {
        version = AppVersion, updateCheck = UpdateCheckEnabled(),
        localCollection = ServerConfigService.LocalCollects, os = AppInfo.OsName,
    });

    [HttpPut("app")]
    public async Task<IActionResult> PutApp([FromBody] AppSettingsRequest req)
    {
        SettingsStore.Update(root => root["UpdateCheck"] = req.UpdateCheck);
        await _audit.WriteAsync(HttpContext, "app.updateCheck", $"enabled={req.UpdateCheck}");
        return Ok(new { version = AppVersion, updateCheck = req.UpdateCheck });
    }

    internal static string AppVersion => AppInfo.Version;

    // On by default
    private static bool UpdateCheckEnabled() =>
        SettingsStore.Load()["UpdateCheck"] is not JsonValue v || !v.TryGetValue<bool>(out var b) || b;

    // GET /api/settings/recording?server=  — exclusions and read merging
    [HttpGet("recording")]
    public async Task<IActionResult> GetRecording([FromQuery] string? server = null)
    {
        if (await CheckServerAsync(server) is { } error) return error;
        return Ok(await _servers.GetRecordingAsync(server));
    }

    [HttpPut("recording")]
    public async Task<IActionResult> PutRecording([FromBody] RecordingSettings req, [FromQuery] string? server = null)
    {
        if (await CheckServerAsync(server) is { } error) return error;
        if (req.MergeReadMinutes < 0 || req.MergeReadMinutes > RecordingSettings.MaxMergeReadMinutes)
            return BadRequest(new { error = Messages.Get("recording.invalidMinutes", RecordingSettings.MaxMergeReadMinutes) });

        static List<string> Clean(IEnumerable<string>? items) =>
            (items ?? []).Select(s => s.Trim()).Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var settings = new RecordingSettings
        {
            ExcludeFilePatterns = Clean(req.ExcludeFilePatterns),
            ExcludeUsers = Clean(req.ExcludeUsers),
            ExcludeProcesses = Clean(req.ExcludeProcesses),
            MergeReadMinutes = req.MergeReadMinutes,
        };
        if (new[] { settings.ExcludeFilePatterns, settings.ExcludeUsers, settings.ExcludeProcesses }
            .Any(list => list.Count > 200 || list.Any(s => s.Length > 260)))
            return BadRequest(new { error = Messages.Get("recording.tooMany") });

        await _servers.SaveRecordingAsync(server, settings);
        await _audit.WriteAsync(HttpContext, "recording.update",
            $"server={ServerLabel(server)}, files=[{string.Join(", ", settings.ExcludeFilePatterns)}], " +
            $"users=[{string.Join(", ", settings.ExcludeUsers)}], processes=[{string.Join(", ", settings.ExcludeProcesses)}], " +
            $"mergeReadMinutes={settings.MergeReadMinutes}");
        return Ok(new { message = Messages.Get("recording.saved"), settings });
    }

    [HttpPost("paths")]
    public async Task<IActionResult> AddPath([FromBody] PathRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Path))
            return BadRequest(new { error = Messages.Get("path.required") });
        if (await CheckServerAsync(req.Server) is { } serverError) return serverError;

        var configs = await _servers.GetPathsAsync(req.Server);
        if (configs.Any(c => c.Path.Equals(req.Path, StringComparison.OrdinalIgnoreCase)))
            return Conflict(new { error = Messages.Get("path.duplicate") });

        var eventTypes = (req.EventTypes is { Length: > 0 } et)
            ? et.Where(t => DefaultEventTypes.Contains(t)).ToArray()
            : DefaultEventTypes;

        var (sacl, error) = await ApplySaclOnAsync(req.Server, req.Path);
        if (error != null) return error;

        var updated = configs.Append(new PathConfig(req.Path, eventTypes)).ToArray();
        await _servers.SavePathsAsync(req.Server, updated);
        _logger.LogInformation("Path added via Web GUI: {Server} {Path}", ServerLabel(req.Server), req.Path);
        await _audit.WriteAsync(HttpContext, "path.add",
            $"server={ServerLabel(req.Server)}, path={req.Path}, eventTypes={string.Join(",", eventTypes)}, " +
            $"sacl={sacl.Count}, saclErrors={sacl.Errors.Count}");

        return Ok(new
        {
            message = sacl.Message("path.added"),
            saclCount = sacl.Count,
            saclErrors = sacl.Errors,
            pathConfigs = updated
        });
    }

    [HttpDelete("paths")]
    public async Task<IActionResult> RemovePath([FromQuery] string path, [FromQuery] bool removeSacl = false,
        [FromQuery] string? server = null)
    {
        if (string.IsNullOrWhiteSpace(path))
            return BadRequest(new { error = Messages.Get("path.paramRequired") });
        if (await CheckServerAsync(server) is { } serverError) return serverError;

        var configs = await _servers.GetPathsAsync(server);
        var updated = configs.Where(c => !c.Path.Equals(path, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (updated.Length == configs.Length)
            return NotFound(new { error = Messages.Get("path.notMonitored") });

        var sacl = new SaclResult(0, []);
        if (removeSacl)
        {
            var (result, error) = await RunJobAsync(server, "removeSacl", new JsonObject { ["path"] = path });
            if (error != null) return error;
            sacl = SaclResult.From(result!); // a folder that is gone has nothing to remove
        }
        await _servers.SavePathsAsync(server, updated);

        _logger.LogInformation("Path removed via Web GUI: {Server} {Path} (removeSacl={RemoveSacl})", ServerLabel(server), path, removeSacl);
        await _audit.WriteAsync(HttpContext, "path.remove",
            $"server={ServerLabel(server)}, path={path}, removeSacl={removeSacl}, sacl={sacl.Count}");

        var message = removeSacl ? sacl.Message("path.removedSacl") : Messages.Get("path.removed");
        return Ok(new { message, saclCount = sacl.Count, saclErrors = sacl.Errors, pathConfigs = updated });
    }

    [HttpPost("paths/apply-sacl")]
    public async Task<IActionResult> ApplySacl([FromBody] PathRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Path))
            return BadRequest(new { error = Messages.Get("path.required") });
        if (await CheckServerAsync(req.Server) is { } serverError) return serverError;

        var (sacl, error) = await ApplySaclOnAsync(req.Server, req.Path);
        if (error != null) return error;
        await _audit.WriteAsync(HttpContext, "path.applySacl",
            $"server={ServerLabel(req.Server)}, path={req.Path}, sacl={sacl.Count}, saclErrors={sacl.Errors.Count}");

        return Ok(new
        {
            message = sacl.Message("path.saclApplied"),
            saclCount = sacl.Count,
            saclErrors = sacl.Errors
        });
    }

    [HttpPost("paths/event-types")]
    public async Task<IActionResult> UpdateEventTypes([FromBody] EventTypesRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Path))
            return BadRequest(new { error = Messages.Get("path.required") });
        if (await CheckServerAsync(req.Server) is { } serverError) return serverError;

        var validTypes = req.EventTypes.Where(t => DefaultEventTypes.Contains(t)).ToArray();
        if (validTypes.Length == 0)
            return BadRequest(new { error = Messages.Get("path.eventTypeRequired") });

        var configs = await _servers.GetPathsAsync(req.Server);
        if (!configs.Any(c => c.Path.Equals(req.Path, StringComparison.OrdinalIgnoreCase)))
            return NotFound(new { error = Messages.Get("path.notMonitored") });

        var updated = configs.Select(c =>
            c.Path.Equals(req.Path, StringComparison.OrdinalIgnoreCase)
                ? c with { EventTypes = validTypes }
                : c).ToArray();

        await _servers.SavePathsAsync(req.Server, updated);
        _logger.LogInformation("EventTypes updated for {Server} {Path}: {Types}", ServerLabel(req.Server), req.Path, string.Join(",", validTypes));
        await _audit.WriteAsync(HttpContext, "path.eventTypes",
            $"server={ServerLabel(req.Server)}, path={req.Path}, eventTypes={string.Join(",", validTypes)}");
        return Ok(new { pathConfigs = updated });
    }

    private static string ServerLabel(string? server) =>
        ServerConfigService.IsLocal(server) ? ServerConfigService.LocalName : server!;

    // An unknown server name is an error; so is this machine when it does not collect
    private async Task<IActionResult?> CheckServerAsync(string? server)
    {
        if (ServerConfigService.IsLocal(server))
            return ServerConfigService.LocalCollects ? null : BadRequest(new { error = Messages.Get("local.notCollecting") });
        return await _servers.FindAgentAsync(server!) != null ? null : NotFound(new { error = Messages.Get("agents.notFound") });
    }

    // Count: files and folders given a SACL, or, with Samba on Linux, shares audited
    private record SaclResult(int Count, List<string> Errors, bool Samba = false)
    {
        public static SaclResult From(JsonObject o) => new(
            o["count"]?.GetValue<int>() ?? 0,
            o["errors"] is JsonArray a ? a.Select(e => e?.GetValue<string>() ?? "").ToList() : [],
            o["kind"]?.GetValue<string>() == "samba");

        public string Message(string key) => Messages.Get(Samba ? key + "Samba" : key, Count);
    }

    // Checks the folder exists and sets up its auditing, here or on the agent's server
    private async Task<(SaclResult Result, IActionResult? Error)> ApplySaclOnAsync(string? server, string path)
    {
        var (result, error) = await RunJobAsync(server, "applySacl", new JsonObject { ["path"] = path });
        if (error != null) return (new(0, []), error);
        if (result!["exists"]?.GetValue<bool>() != true)
            return (new(0, []), BadRequest(new { error = Messages.Get("path.notFound", path) }));
        return (SaclResult.From(result), null);
    }

    // A job on this machine (CheckServerAsync has made sure it collects) or on the agent's server
    private async Task<(JsonObject? Result, IActionResult? Error)> RunJobAsync(string? server, string type, JsonObject args)
    {
        if (!ServerConfigService.IsLocal(server)) return await RunOnAgentAsync(server!, type, args);
        if (_local == null) return (null, BadRequest(new { error = Messages.Get("local.notCollecting") }));
        var result = await Task.Run(() => _local.RunJob(new AgentJob("local", type, args), HttpContext.RequestAborted));
        if (result["error"]?.GetValue<string>() is { } message) return (null, BadRequest(new { error = message }));
        return (result, null);
    }

    private async Task<(JsonObject? Result, IActionResult? Error)> RunOnAgentAsync(string server, string type, JsonObject args)
    {
        var agent = await _servers.FindAgentAsync(server);
        if (agent == null) return (null, NotFound(new { error = Messages.Get("agents.notFound") }));
        if (agent.Disabled) return (null, BadRequest(new { error = Messages.Get("agents.isDisabled", agent.Name) }));
        try
        {
            var result = await _jobs.RunAsync(agent.Id, type, args, SaclJobTimeout, HttpContext.RequestAborted);
            if (result["error"]?.GetValue<string>() is { } message)
                return (null, BadRequest(new { error = Messages.Get("agents.jobFailed", agent.Name, message) }));
            return (result, null);
        }
        catch (TimeoutException)
        {
            return (null, StatusCode(StatusCodes.Status504GatewayTimeout, new { error = Messages.Get("agents.noAnswer", agent.Name) }));
        }
    }

    internal static JsonArray PathConfigsToJson(PathConfig[] configs) => new(configs
        .Select(c => (JsonNode)new JsonObject
        {
            ["path"] = c.Path,
            ["eventTypes"] = new JsonArray(c.EventTypes.Select(t => (JsonNode)JsonValue.Create(t)).ToArray())
        })
        .ToArray());

    internal static (PathConfig[] configs, string dnsServer) ReadSettingsDoc() => ParseSettings(SettingsStore.Load());

    internal static (PathConfig[] configs, string dnsServer) ParseSettings(JsonObject root)
    {
        var dns = root["DnsServer"] is JsonValue d && d.TryGetValue<string>(out var s) ? s : "";
        return (MonitoredPathList.Parse(root).Select(p => new PathConfig(p.Path, p.EventTypes)).ToArray(), dns);
    }
}

public record PathConfig(string Path, string[] EventTypes);
public record PathRequest(string Path, string[]? EventTypes = null, string? Server = null);
public record EventTypesRequest(string Path, string[] EventTypes, string? Server = null);
public record DnsRequest(string? DnsServer);
public record AppSettingsRequest(bool UpdateCheck);
