using System.Text.Json.Nodes;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Mvc;

namespace FileAccessMonitor.Controllers;

[ApiController]
[Route("api/[controller]")]
[Microsoft.AspNetCore.Authorization.Authorize(Roles = "Admin")]
public class SettingsController : ControllerBase
{
    private static readonly string[] DefaultEventTypes = ["Read", "Write", "Delete"];

    private readonly SaclManagerService _sacl;
    private readonly DnsResolverService _dns;
    private readonly AuditLog _audit;
    private readonly ILogger<SettingsController> _logger;

    public SettingsController(SaclManagerService sacl, DnsResolverService dns,
        AuditLog audit, ILogger<SettingsController> logger)
    {
        _sacl = sacl;
        _dns = dns;
        _audit = audit;
        _logger = logger;
    }

    [HttpGet]
    public IActionResult Get()
    {
        var (configs, dns) = ReadSettingsDoc();
        return Ok(new { pathConfigs = configs, dnsServer = dns });
    }

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
    public IActionResult GetApp() => Ok(new { version = AppVersion, updateCheck = UpdateCheckEnabled() });

    [HttpPut("app")]
    public async Task<IActionResult> PutApp([FromBody] AppSettingsRequest req)
    {
        SettingsStore.Update(root => root["UpdateCheck"] = req.UpdateCheck);
        await _audit.WriteAsync(HttpContext, "app.updateCheck", $"enabled={req.UpdateCheck}");
        return Ok(new { version = AppVersion, updateCheck = req.UpdateCheck });
    }

    // "1.3.0" from the informational version ("1.3.0+<commit>"); "0.0.0" for local builds
    internal static readonly string AppVersion =
        (typeof(SettingsController).Assembly
            .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .FirstOrDefault() as System.Reflection.AssemblyInformationalVersionAttribute)?.InformationalVersion
            .Split('+')[0] ?? "0.0.0";

    // On by default
    private static bool UpdateCheckEnabled() =>
        SettingsStore.Load()["UpdateCheck"] is not JsonValue v || !v.TryGetValue<bool>(out var b) || b;

    // GET /api/settings/recording  — exclusions and read merging
    [HttpGet("recording")]
    public IActionResult GetRecording() => Ok(RecordingSettings.Load());

    [HttpPut("recording")]
    public async Task<IActionResult> PutRecording([FromBody] RecordingSettings req)
    {
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

        settings.Save();
        await _audit.WriteAsync(HttpContext, "recording.update",
            $"files=[{string.Join(", ", settings.ExcludeFilePatterns)}], users=[{string.Join(", ", settings.ExcludeUsers)}], " +
            $"processes=[{string.Join(", ", settings.ExcludeProcesses)}], mergeReadMinutes={settings.MergeReadMinutes}");
        return Ok(new { message = Messages.Get("recording.saved"), settings });
    }

    [HttpPost("paths")]
    public async Task<IActionResult> AddPath([FromBody] PathRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Path))
            return BadRequest(new { error = Messages.Get("path.required") });

        if (!Directory.Exists(req.Path))
            return BadRequest(new { error = Messages.Get("path.notFound", req.Path) });

        var (configs, _) = ReadSettingsDoc();
        if (configs.Any(c => c.Path.Equals(req.Path, StringComparison.OrdinalIgnoreCase)))
            return Conflict(new { error = Messages.Get("path.duplicate") });

        var eventTypes = (req.EventTypes is { Length: > 0 } et)
            ? et.Where(t => DefaultEventTypes.Contains(t)).ToArray()
            : DefaultEventTypes;

        var updated = configs.Append(new PathConfig(req.Path, eventTypes)).ToArray();
        SavePathConfigs(updated);

        _sacl.EnableAuditPolicy();
        var (count, errors) = _sacl.ApplySacl(req.Path);
        _logger.LogInformation("Path added via Web GUI: {Path}", req.Path);
        await _audit.WriteAsync(HttpContext, "path.add",
            $"path={req.Path}, eventTypes={string.Join(",", eventTypes)}, sacl={count}, saclErrors={errors.Count}");

        return Ok(new
        {
            message = Messages.Get("path.added", count),
            saclCount = count,
            saclErrors = errors,
            pathConfigs = updated
        });
    }

    [HttpDelete("paths")]
    public async Task<IActionResult> RemovePath([FromQuery] string path, [FromQuery] bool removeSacl = false)
    {
        if (string.IsNullOrWhiteSpace(path))
            return BadRequest(new { error = Messages.Get("path.paramRequired") });

        var (configs, _) = ReadSettingsDoc();
        var updated = configs.Where(c => !c.Path.Equals(path, StringComparison.OrdinalIgnoreCase)).ToArray();

        if (updated.Length == configs.Length)
            return NotFound(new { error = Messages.Get("path.notMonitored") });

        SavePathConfigs(updated);

        int saclCount = 0;
        List<string> saclErrors = [];
        if (removeSacl && Directory.Exists(path))
            (saclCount, saclErrors) = _sacl.RemoveSacl(path);

        _logger.LogInformation("Path removed via Web GUI: {Path} (removeSacl={RemoveSacl})", path, removeSacl);
        await _audit.WriteAsync(HttpContext, "path.remove", $"path={path}, removeSacl={removeSacl}, sacl={saclCount}");

        var message = removeSacl
            ? Messages.Get("path.removedSacl", saclCount)
            : Messages.Get("path.removed");

        return Ok(new { message, saclCount, saclErrors, pathConfigs = updated });
    }

    [HttpPost("paths/apply-sacl")]
    public async Task<IActionResult> ApplySacl([FromBody] PathRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Path))
            return BadRequest(new { error = Messages.Get("path.required") });

        if (!Directory.Exists(req.Path))
            return BadRequest(new { error = Messages.Get("path.notFound", req.Path) });

        _sacl.EnableAuditPolicy();
        var (count, errors) = _sacl.ApplySacl(req.Path);
        await _audit.WriteAsync(HttpContext, "path.applySacl", $"path={req.Path}, sacl={count}, saclErrors={errors.Count}");

        return Ok(new
        {
            message = Messages.Get("path.saclApplied", count),
            saclCount = count,
            saclErrors = errors
        });
    }

    [HttpPost("paths/event-types")]
    public async Task<IActionResult> UpdateEventTypes([FromBody] EventTypesRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Path))
            return BadRequest(new { error = Messages.Get("path.required") });

        var validTypes = req.EventTypes.Where(t => DefaultEventTypes.Contains(t)).ToArray();
        if (validTypes.Length == 0)
            return BadRequest(new { error = Messages.Get("path.eventTypeRequired") });

        var (configs, _) = ReadSettingsDoc();
        if (!configs.Any(c => c.Path.Equals(req.Path, StringComparison.OrdinalIgnoreCase)))
            return NotFound(new { error = Messages.Get("path.notMonitored") });

        var updated = configs.Select(c =>
            c.Path.Equals(req.Path, StringComparison.OrdinalIgnoreCase)
                ? c with { EventTypes = validTypes }
                : c).ToArray();

        SavePathConfigs(updated);
        _logger.LogInformation("EventTypes updated for {Path}: {Types}", req.Path, string.Join(",", validTypes));
        await _audit.WriteAsync(HttpContext, "path.eventTypes", $"path={req.Path}, eventTypes={string.Join(",", validTypes)}");
        return Ok(new { pathConfigs = updated });
    }

    private static void SavePathConfigs(PathConfig[] configs) =>
        SettingsStore.Update(root => root["MonitoredPaths"] = new JsonArray(configs
            .Select(c => (JsonNode)new JsonObject
            {
                ["path"] = c.Path,
                ["eventTypes"] = new JsonArray(c.EventTypes.Select(t => (JsonNode)JsonValue.Create(t)).ToArray())
            })
            .ToArray()));

    internal static (PathConfig[] configs, string dnsServer) ReadSettingsDoc() => ParseSettings(SettingsStore.Load());

    internal static (PathConfig[] configs, string dnsServer) ParseSettings(JsonObject root)
    {
        var dns = root["DnsServer"] is JsonValue d && d.TryGetValue<string>(out var s) ? s : "";

        var list = new List<PathConfig>();
        if (root["MonitoredPaths"] is JsonArray arr)
        {
            foreach (var el in arr)
            {
                if (el is JsonValue v && v.TryGetValue<string>(out var p))
                {
                    // old format: plain string → upgrade to all types
                    if (!string.IsNullOrEmpty(p)) list.Add(new PathConfig(p, DefaultEventTypes));
                }
                else if (el is JsonObject o && o["path"] is JsonValue pv && pv.TryGetValue<string>(out var path)
                         && !string.IsNullOrEmpty(path))
                {
                    var types = o["eventTypes"] is JsonArray ta
                        ? ta.Select(t => t is JsonValue tv && tv.TryGetValue<string>(out var ts) ? ts : "")
                            .Where(t => t.Length > 0).ToArray()
                        : DefaultEventTypes;
                    list.Add(new PathConfig(path, types));
                }
            }
        }
        return ([.. list], dns);
    }
}

public record PathConfig(string Path, string[] EventTypes);
public record PathRequest(string Path, string[]? EventTypes = null);
public record EventTypesRequest(string Path, string[] EventTypes);
public record DnsRequest(string? DnsServer);
public record AppSettingsRequest(bool UpdateCheck);
