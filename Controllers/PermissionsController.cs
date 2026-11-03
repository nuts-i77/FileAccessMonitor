using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Controllers;

// The permissions below a monitored folder, as of the last scan: who may do what, broad access,
// folders that do not inherit. Scans cost the file server time and are started by Admins only. As
// the report names folders and groups, only Admins and Viewers with a folder scope may read it, and
// a scoped Viewer sees the rows inside their scope.
[ApiController]
[Route("api/permissions")]
[Authorize]
public class PermissionsController : ControllerBase
{
    private const int MaxExportLines = 200_000;
    private const int MaxPageSize = 1000;

    private readonly PermissionReportService _reports;
    private readonly AccessDbContext _db;
    private readonly UserScopeService _scopes;
    private readonly ServerConfigService _servers;
    private readonly AuditLog _audit;

    public PermissionsController(PermissionReportService reports, AccessDbContext db, UserScopeService scopes,
        ServerConfigService servers, AuditLog audit)
    {
        _reports = reports;
        _db = db;
        _scopes = scopes;
        _servers = servers;
        _audit = audit;
    }

    // GET /api/permissions/servers : the servers the signed-in user may look at
    [HttpGet("servers")]
    public async Task<IActionResult> Servers()
    {
        if (!Allowed(out var scope)) return NoAccess();
        var names = await _servers.ServerNamesAsync();
        if (scope != null)
            names = names.Where(n => scope.Any(e => e.Server == null || e.Server.Equals(n, StringComparison.OrdinalIgnoreCase))).ToList();
        return Ok(new { local = ServerConfigService.LocalName, servers = names });
    }

    // GET /api/permissions/roots?server= : monitored folders with the age of their stored scan
    [HttpGet("roots")]
    public async Task<IActionResult> Roots([FromQuery] string? server = null, CancellationToken ct = default)
    {
        if (!Allowed(out var scope)) return NoAccess();
        var (name, _, error) = await ResolveAsync(server, forScan: false);
        if (error != null) return error;
        var roots = (await _servers.GetPathsAsync(server)).Select(c => PathText.Normalize(c.Path))
            .Where(p => InScope(scope, name, p));
        var list = new List<object>();
        foreach (var root in roots)
        {
            var last = await _reports.GetLastAsync(name, root, ct);
            list.Add(new
            {
                path = root, scannedAt = last?.ScannedAt, folders = last?.Result["folders"]?.GetValue<int>(),
                files = last?.Result["files"]?.GetValue<int>(), truncated = last?.Result["truncated"]?.GetValue<bool>(),
            });
        }
        return Ok(new { server = name, roots = list, canScan = scope == null });
    }

    public record ScanRequest(string? Server, string? Folder, int? MaxFolders, int? MaxFiles, int? MaxDepth, bool? IncludeFiles);

    // POST /api/permissions/scan : scans the folder now and stores the result
    [HttpPost("scan")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> Scan([FromBody] ScanRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Folder)) return BadRequest(new { error = Messages.Get("path.required") });
        var folder = PathText.Normalize(request.Folder);
        var (name, agent, error) = await ResolveAsync(request.Server, forScan: true);
        if (error != null) return error;
        var configs = await _servers.GetPathsAsync(request.Server);
        if (!configs.Any(c => PathText.IsUnder(folder, c.Path)))
            return BadRequest(new { error = Messages.Get("path.notMonitored") });

        var defaults = new PermissionScanOptions();
        var options = new PermissionScanOptions(request.MaxFolders ?? defaults.MaxFolders, request.MaxFiles ?? defaults.MaxFiles,
            request.MaxDepth ?? defaults.MaxDepth, request.IncludeFiles ?? defaults.IncludeFiles);
        StoredPermissionReport report;
        try
        {
            report = await _reports.ScanAsync(name, folder, options, ct);
        }
        catch (PermissionScanException ex)
        {
            return StatusCode(ex.Status, new { error = ex.Message });
        }
        await _audit.WriteAsync(HttpContext, "permissions.scan",
            $"server={name}, folder={folder}, rows={report.Result["rows"]?.AsArray().Count ?? 0}, " +
            $"truncated={report.Result["truncated"]?.GetValue<bool>() ?? false}, ms={report.Result["elapsedMs"]?.GetValue<long>() ?? 0}");
        return Ok(await BuildViewAsync(report, null, new ViewFilter(false, false, null, 1, 200), ct));
    }

    // GET /api/permissions?server=&folder=&broadOnly=false&brokenOnly=false&q=&page=1&pageSize=200
    [HttpGet]
    public async Task<IActionResult> Get([FromQuery] string? server, [FromQuery] string folder, [FromQuery] bool broadOnly = false,
        [FromQuery] bool brokenOnly = false, [FromQuery] string? q = null, [FromQuery] int page = 1,
        [FromQuery] int pageSize = 200, CancellationToken ct = default)
    {
        if (!Allowed(out var scope)) return NoAccess();
        var (loaded, error) = await LoadAsync(server, folder, scope, ct);
        if (error != null) return error;
        return Ok(await BuildViewAsync(loaded!, scope, new ViewFilter(broadOnly, brokenOnly, q, Math.Max(1, page),
            Math.Clamp(pageSize, 1, MaxPageSize)), ct));
    }

    // GET /api/permissions/export?(same filters) : one CSV line per entry (UTF-8 with BOM)
    [HttpGet("export")]
    public async Task<IActionResult> Export([FromQuery] string? server, [FromQuery] string folder, [FromQuery] bool broadOnly = false,
        [FromQuery] bool brokenOnly = false, [FromQuery] string? q = null, CancellationToken ct = default)
    {
        if (!Allowed(out var scope)) return NoAccess();
        var (loaded, error) = await LoadAsync(server, folder, scope, ct);
        if (error != null) return error;
        var report = loaded!;

        var rows = Filter(report, scope, new ViewFilter(broadOnly, brokenOnly, q, 1, int.MaxValue));
        var changes = await LastChangesAsync(report, ct);

        string yes = Messages.Get("perm.csv.yes"), no = Messages.Get("perm.csv.no");
        var lines = new List<string>
        {
            StatsController.CsvLine(Messages.Get("perm.csv.server"), Messages.Get("perm.csv.root"), Messages.Get("perm.csv.path"),
                Messages.Get("perm.csv.kind"), Messages.Get("perm.csv.principal"), Messages.Get("perm.csv.sid"),
                Messages.Get("perm.csv.access"), Messages.Get("perm.csv.level"), Messages.Get("perm.csv.appliesTo"),
                Messages.Get("perm.csv.broad"), Messages.Get("perm.csv.severity"), Messages.Get("perm.csv.inheritanceBroken"),
                Messages.Get("perm.csv.owner"), Messages.Get("perm.csv.lastChange"), Messages.Get("perm.csv.lastChangeUser")),
        };
        foreach (var row in rows)
        {
            var change = changes.GetValueOrDefault(row.Path);
            var common = new string?[]
            {
                report.Server, report.Root, row.Path, Messages.Get(row.IsFolder ? "perm.csv.folder" : "perm.csv.file"),
            };
            string?[] tail =
            [
                row.InheritanceBroken ? yes : no, row.Owner,
                change == null ? "" : change.Time.ToString("yyyy-MM-ddTHH:mm:ssZ"), change?.User,
            ];
            if (row.Aces.Count == 0)
                lines.Add(StatsController.CsvLine([.. common, row.NotReadable ? Messages.Get("perm.csv.notReadable") : "", "", "", "", "", "", "", .. tail]));
            foreach (var a in row.Aces)
                lines.Add(StatsController.CsvLine([.. common, a.Principal, a.Sid, Messages.Get(a.Kind == "deny" ? "perm.csv.deny" : "perm.csv.allow"),
                    LevelText(a.Level), row.IsFolder || report.Os == "linux" ? ScopeText(a.Scope) : "", a.Broad, SeverityText(a.Severity), .. tail]));
            if (lines.Count > MaxExportLines) break;
        }

        var rowCount = lines.Count - 1;
        await _audit.WriteAsync(HttpContext, "permissions.export", $"server={report.Server}, folder={report.Root}, rows={rowCount}");
        var bytes = new System.Text.UTF8Encoding(true).GetPreamble()
            .Concat(new System.Text.UTF8Encoding(false).GetBytes(string.Join("\r\n", lines) + "\r\n")).ToArray();
        return File(bytes, "text/csv; charset=utf-8", $"permissions-{DateTime.UtcNow:yyyyMMdd-HHmm}.csv");
    }

    // ── Helpers ───────────────────────────────────────────────────

    private bool Allowed(out List<ScopeEntry>? scope)
    {
        scope = _scopes.Get(User);
        return User.IsInRole("Admin") || scope != null;
    }

    private IActionResult NoAccess() => StatusCode(StatusCodes.Status403Forbidden, new { error = Messages.Get("perm.noAccess") });

    // Whether a viewer may look at this folder: the scope holds it or a folder inside it
    private static bool InScope(List<ScopeEntry>? scope, string server, string folder) =>
        scope == null || scope.Any(e => (e.Server == null || e.Server.Equals(server, StringComparison.OrdinalIgnoreCase))
                                        && (PathText.IsUnder(folder, e.Path) || PathText.IsUnder(e.Path, folder)));

    // The server's own name and its agent (null for this machine); an error answer when it cannot be used
    private async Task<(string Name, Agent? Agent, IActionResult? Error)> ResolveAsync(string? server, bool forScan)
    {
        if (ServerConfigService.IsLocal(server))
        {
            if (forScan && !ServerConfigService.LocalCollects)
                return ("", null, BadRequest(new { error = Messages.Get("local.notCollecting") }));
            return (ServerConfigService.LocalName, null, null);
        }
        var agent = await _servers.FindAgentAsync(server!);
        if (agent == null) return ("", null, NotFound(new { error = Messages.Get("agents.notFound") }));
        if (forScan && agent.Disabled) return ("", null, BadRequest(new { error = Messages.Get("agents.isDisabled", agent.Name) }));
        return (agent.Name, agent, null);
    }

    private async Task<(StoredPermissionReport? Report, IActionResult? Error)> LoadAsync(string? server, string? folder,
        List<ScopeEntry>? scope, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(folder)) return (null, BadRequest(new { error = Messages.Get("path.required") }));
        var (name, _, error) = await ResolveAsync(server, forScan: false);
        if (error != null) return (null, error);
        folder = PathText.Normalize(folder);
        if (!InScope(scope, name, folder))
            return (null, StatusCode(StatusCodes.Status403Forbidden, new { error = Messages.Get("scope.outside") }));
        var report = await _reports.GetLastAsync(name, folder, ct);
        return report == null ? (null, NotFound(new { error = Messages.Get("perm.noScan") })) : (report, null);
    }

    internal record ViewFilter(bool BroadOnly, bool BrokenOnly, string? Text, int Page, int PageSize);

    // The scan's rows inside the scope, filtered, in tree order
    private static List<ViewRow> Filter(StoredPermissionReport report, List<ScopeEntry>? scope, ViewFilter f)
    {
        var rows = PermissionReportView.Rows(report, PermissionReportView.ExtraBroadPrincipals()).AsEnumerable();
        if (scope != null) rows = rows.Where(r => AccessScope.Contains(scope, report.Server, r.Path));
        if (f.BroadOnly) rows = rows.Where(r => r.Severity.Length > 0);
        if (f.BrokenOnly) rows = rows.Where(r => r.InheritanceBroken);
        if (!string.IsNullOrWhiteSpace(f.Text))
        {
            var text = f.Text.Trim();
            rows = rows.Where(r => r.Path.Contains(text, StringComparison.OrdinalIgnoreCase)
                || r.Aces.Any(a => a.Principal.Contains(text, StringComparison.OrdinalIgnoreCase)));
        }
        return rows.Order(PermissionReportView.TreeOrder(report.Root)).ToList();
    }

    internal record Change(DateTime Time, string User, long RecordId);

    // The latest permission change recorded (v1.9) for each path below the folder
    private async Task<Dictionary<string, Change>> LastChangesAsync(StoredPermissionReport report, CancellationToken ct)
    {
        var sep = PathText.SeparatorOf(report.Root);
        var prefix = AccessScope.Escape(report.Root.TrimEnd(sep) + sep) + "%";
        var self = AccessScope.Escape(report.Root);
        var records = await _db.AccessRecords.AsNoTracking()
            .Where(r => r.ServerName == report.Server && r.AccessType == AccessTypes.Permission && !r.Denied
                && (EF.Functions.Like(r.FilePath, prefix, "\\") || EF.Functions.Like(r.FilePath, self, "\\")))
            .OrderByDescending(r => r.AccessTime).Take(100_000)
            .Select(r => new { r.FilePath, r.AccessTime, r.UserName, r.Id })
            .ToListAsync(ct);
        var latest = new Dictionary<string, Change>(PathText.ComparerOf(report.Root));
        foreach (var r in records)
            latest.TryAdd(r.FilePath, new Change(DateTime.SpecifyKind(r.AccessTime, DateTimeKind.Utc), r.UserName, r.Id));
        return latest;
    }

    private async Task<object> BuildViewAsync(StoredPermissionReport report, List<ScopeEntry>? scope, ViewFilter f, CancellationToken ct)
    {
        var all = Filter(report, scope, new ViewFilter(false, false, null, 1, int.MaxValue));
        var rows = Filter(report, scope, f);
        var page = rows.Skip((f.Page - 1) * f.PageSize).Take(f.PageSize).ToList();
        var changes = await LastChangesAsync(report, ct);

        var rootInScope = scope == null || AccessScope.Contains(scope, report.Server, report.Root);
        var shares = rootInScope ? PermissionReportView.Shares(report) : [];
        return new
        {
            server = report.Server, folder = report.Root, os = report.Os, agentVersion = report.AgentVersion,
            scannedAt = report.ScannedAt,
            folders = report.Result["folders"]?.GetValue<int>() ?? 0, files = report.Result["files"]?.GetValue<int>() ?? 0,
            truncated = report.Result["truncated"]?.GetValue<bool>() ?? false, limit = report.Result["limit"]?.GetValue<string>(),
            elapsedMs = report.Result["elapsedMs"]?.GetValue<long>() ?? 0,
            errors = rootInScope ? (report.Result["errors"] as System.Text.Json.Nodes.JsonArray ?? []).Select(e => e?.GetValue<string>()) : [],
            shares = shares.Select(s => new { s.Name, s.Path, s.GuestOk, s.ReadOnly, s.ValidUsers, s.WriteList, s.NtAcl, s.Severity }),
            scoped = scope != null,
            canScan = User.IsInRole("Admin"),
            counts = new
            {
                high = all.Count(r => r.Severity == PermissionAnalysis.High) + shares.Count(s => s.Severity == PermissionAnalysis.High),
                medium = all.Count(r => r.Severity == PermissionAnalysis.Medium) + shares.Count(s => s.Severity == PermissionAnalysis.Medium),
                broken = all.Count(r => r.InheritanceBroken),
                notReadable = all.Count(r => r.NotReadable),
                rows = all.Count,
            },
            total = rows.Count, page = f.Page, pageSize = f.PageSize,
            items = page.Select(r =>
            {
                var change = changes.GetValueOrDefault(r.Path);
                return new
                {
                    path = r.Path, rel = r.Rel, depth = r.Depth, isFolder = r.IsFolder, inheritanceBroken = r.InheritanceBroken,
                    notReadable = r.NotReadable, hasAcl = (r.Flags & PermissionContract.FlagAcl) != 0,
                    hasDefaultAcl = (r.Flags & PermissionContract.FlagDefaultAcl) != 0,
                    ownerDiffers = (r.Flags & PermissionContract.FlagOwnerDiffers) != 0, owner = r.Owner, severity = r.Severity,
                    aces = r.Aces.Select(a => new
                    {
                        principal = a.Principal, sid = a.Sid, kind = a.Kind, level = a.Level,
                        levelCode = PermissionContract.LevelCode(a.Level), scope = a.Scope, levelBeforeMask = a.LevelBeforeMask,
                        broad = a.Broad, severity = a.Severity,
                    }),
                    lastChange = change == null ? null : new { time = change.Time, user = change.User, recordId = change.RecordId },
                    changedSinceScan = change != null && change.Time > report.ScannedAt,
                };
            }),
        };
    }

    private static string LevelText(int level)
    {
        var code = PermissionContract.LevelCode(level);
        return code == "special" ? Messages.Get("perm.csv.level.special", level.ToString("X")) : Messages.Get("perm.csv.level." + code);
    }

    private static string ScopeText(int scope) => (scope & 7) == 0 ? "" : Messages.Get("perm.csv.scope." + (scope & 7));

    private static string? SeverityText(string? severity) => severity switch
    {
        PermissionAnalysis.High => Messages.Get("perm.csv.high"),
        PermissionAnalysis.Medium => Messages.Get("perm.csv.medium"),
        _ => "",
    };
}
