using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Mvc;

namespace FileAccessMonitor.Controllers;

[ApiController]
[Route("api/[controller]")]
[Microsoft.AspNetCore.Authorization.Authorize(Roles = "Admin")]
public class SettingsController : ControllerBase
{
    private static readonly string SettingsFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "FileAccessMonitor", "settings.json");

    private static readonly string[] DefaultEventTypes = ["Read", "Write", "Delete"];

    private readonly IConfiguration _config;
    private readonly SaclManagerService _sacl;
    private readonly DnsResolverService _dns;
    private readonly ILogger<SettingsController> _logger;

    public SettingsController(IConfiguration config, SaclManagerService sacl,
        DnsResolverService dns, ILogger<SettingsController> logger)
    {
        _config = config;
        _sacl = sacl;
        _dns = dns;
        _logger = logger;
    }

    [HttpGet]
    public IActionResult Get()
    {
        var (configs, dns) = ReadSettingsDoc();
        return Ok(new { pathConfigs = configs, dnsServer = dns });
    }

    [HttpPost("dns")]
    public IActionResult SetDns([FromBody] DnsRequest req)
    {
        var server = req.DnsServer?.Trim() ?? "";
        _dns.SetDnsServer(server);
        SaveDnsServer(server);
        _logger.LogInformation("DNS server updated: {Dns}", server);
        return Ok(new { dnsServer = server });
    }

    [HttpPost("paths")]
    public IActionResult AddPath([FromBody] PathRequest req)
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
        SaveSettings(updated);

        _sacl.EnableAuditPolicy();
        var (count, errors) = _sacl.ApplySacl(req.Path);
        _logger.LogInformation("Path added via Web GUI: {Path}", req.Path);

        return Ok(new
        {
            message = Messages.Get("path.added", count),
            saclCount = count,
            saclErrors = errors,
            pathConfigs = updated
        });
    }

    [HttpDelete("paths")]
    public IActionResult RemovePath([FromQuery] string path, [FromQuery] bool removeSacl = false)
    {
        if (string.IsNullOrWhiteSpace(path))
            return BadRequest(new { error = Messages.Get("path.paramRequired") });

        var (configs, _) = ReadSettingsDoc();
        var updated = configs.Where(c => !c.Path.Equals(path, StringComparison.OrdinalIgnoreCase)).ToArray();

        if (updated.Length == configs.Length)
            return NotFound(new { error = Messages.Get("path.notMonitored") });

        SaveSettings(updated);

        int saclCount = 0;
        List<string> saclErrors = [];
        if (removeSacl && Directory.Exists(path))
            (saclCount, saclErrors) = _sacl.RemoveSacl(path);

        _logger.LogInformation("Path removed via Web GUI: {Path} (removeSacl={RemoveSacl})", path, removeSacl);

        var message = removeSacl
            ? Messages.Get("path.removedSacl", saclCount)
            : Messages.Get("path.removed");

        return Ok(new { message, saclCount, saclErrors, pathConfigs = updated });
    }

    [HttpPost("paths/apply-sacl")]
    public IActionResult ApplySacl([FromBody] PathRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Path))
            return BadRequest(new { error = Messages.Get("path.required") });

        if (!Directory.Exists(req.Path))
            return BadRequest(new { error = Messages.Get("path.notFound", req.Path) });

        _sacl.EnableAuditPolicy();
        var (count, errors) = _sacl.ApplySacl(req.Path);

        return Ok(new
        {
            message = Messages.Get("path.saclApplied", count),
            saclCount = count,
            saclErrors = errors
        });
    }

    [HttpPost("paths/event-types")]
    public IActionResult UpdateEventTypes([FromBody] EventTypesRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Path))
            return BadRequest(new { error = Messages.Get("path.required") });

        var validTypes = req.EventTypes.Where(t => DefaultEventTypes.Contains(t)).ToArray();
        if (validTypes.Length == 0)
            return BadRequest(new { error = Messages.Get("path.eventTypeRequired") });

        var (configs, _) = ReadSettingsDoc();
        var updated = configs.Select(c =>
            c.Path.Equals(req.Path, StringComparison.OrdinalIgnoreCase)
                ? c with { EventTypes = validTypes }
                : c).ToArray();

        if (!updated.Any(c => c.Path.Equals(req.Path, StringComparison.OrdinalIgnoreCase)))
            return NotFound(new { error = Messages.Get("path.notMonitored") });

        SaveSettings(updated);
        _logger.LogInformation("EventTypes updated for {Path}: {Types}", req.Path, string.Join(",", validTypes));
        return Ok(new { pathConfigs = updated });
    }

    private static void SaveSettings(PathConfig[] configs)
    {
        var (_, dns) = ReadSettingsDoc();
        Directory.CreateDirectory(Path.GetDirectoryName(SettingsFile)!);
        var json = System.Text.Json.JsonSerializer.Serialize(
            new
            {
                MonitoredPaths = configs.Select(c => new { path = c.Path, eventTypes = c.EventTypes }),
                DnsServer = dns
            },
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        System.IO.File.WriteAllText(SettingsFile, json);
    }

    private static void SaveDnsServer(string dnsServer)
    {
        var (configs, _) = ReadSettingsDoc();
        Directory.CreateDirectory(Path.GetDirectoryName(SettingsFile)!);
        var json = System.Text.Json.JsonSerializer.Serialize(
            new
            {
                MonitoredPaths = configs.Select(c => new { path = c.Path, eventTypes = c.EventTypes }),
                DnsServer = dnsServer
            },
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        System.IO.File.WriteAllText(SettingsFile, json);
    }

    internal static (PathConfig[] configs, string dnsServer) ReadSettingsDoc()
    {
        if (!System.IO.File.Exists(SettingsFile)) return ([], "");
        try
        {
            var json = System.IO.File.ReadAllText(SettingsFile);
            var doc = System.Text.Json.JsonDocument.Parse(json);
            var dns = doc.RootElement.TryGetProperty("DnsServer", out var d) ? d.GetString() ?? "" : "";

            var configs = Array.Empty<PathConfig>();
            if (doc.RootElement.TryGetProperty("MonitoredPaths", out var arr))
            {
                var list = new List<PathConfig>();
                foreach (var el in arr.EnumerateArray())
                {
                    if (el.ValueKind == System.Text.Json.JsonValueKind.String)
                    {
                        // old format: plain string → upgrade to all types
                        var p = el.GetString();
                        if (!string.IsNullOrEmpty(p)) list.Add(new PathConfig(p, DefaultEventTypes));
                    }
                    else if (el.ValueKind == System.Text.Json.JsonValueKind.Object)
                    {
                        var p = el.TryGetProperty("path", out var pv) ? pv.GetString() ?? "" : "";
                        if (string.IsNullOrEmpty(p)) continue;
                        var types = el.TryGetProperty("eventTypes", out var tv)
                            ? tv.EnumerateArray().Select(e => e.GetString() ?? "").Where(s => s.Length > 0).ToArray()
                            : DefaultEventTypes;
                        list.Add(new PathConfig(p, types));
                    }
                }
                configs = [.. list];
            }
            return (configs, dns);
        }
        catch { return ([], ""); }
    }
}

public record PathConfig(string Path, string[] EventTypes);
public record PathRequest(string Path, string[]? EventTypes = null);
public record EventTypesRequest(string Path, string[] EventTypes);
public record DnsRequest(string? DnsServer);
