using FileAccessMonitor.Data;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Controllers;

// Files in a monitored folder that nobody read (or accessed at all) in a period. The folder is
// scanned on disk, because files that were never accessed have no records. As it lists file names
// that the access records do not contain, only Admins and Viewers with a folder scope (inside it) may use it.
[ApiController]
[Route("api/unused-files")]
[Authorize]
public class UnusedFilesController : ControllerBase
{
    internal const int MaxScannedFiles = 100_000;
    private const int MaxResults = 2_000;

    // Listing a large share on an agent's server and uploading it can take a while
    private static readonly TimeSpan ScanJobTimeout = TimeSpan.FromMinutes(10);

    private readonly AccessDbContext _db;
    private readonly UserScopeService _scopes;
    private readonly ServerConfigService _servers;
    private readonly AgentJobs _jobs;

    public UnusedFilesController(AccessDbContext db, UserScopeService scopes, ServerConfigService servers, AgentJobs jobs)
    {
        _db = db;
        _scopes = scopes;
        _servers = servers;
        _jobs = jobs;
    }

    // GET /api/unused-files?server=&folder=D:\Share\Video&days=90&criterion=read
    // server: empty = this machine, otherwise an agent's server (its agent lists the folder)
    // days = 0: since the first record; criterion = read (not read) | any (not accessed at all)
    [HttpGet]
    public async Task<IActionResult> Get([FromQuery] string folder, [FromQuery] int days = 90,
        [FromQuery] string criterion = "read", [FromQuery] string? server = null, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(folder))
            return BadRequest(new { error = Messages.Get("path.required") });
        folder = PathText.Normalize(folder);

        var local = ServerConfigService.IsLocal(server);
        if (local && !ServerConfigService.LocalCollects) return BadRequest(new { error = Messages.Get("local.notCollecting") });
        var agent = local ? null : await _servers.FindAgentAsync(server!);
        if (!local && agent == null) return NotFound(new { error = Messages.Get("agents.notFound") });
        var serverName = agent?.Name ?? ServerConfigService.LocalName;

        var configs = await _servers.GetPathsAsync(server);
        if (!configs.Any(c => PathText.IsUnder(folder, c.Path)))
            return BadRequest(new { error = Messages.Get("path.notMonitored") });
        if (!User.IsInRole("Admin") && !(_scopes.Get(User) is { } scope && AccessScope.Contains(scope, serverName, folder)))
            return StatusCode(StatusCodes.Status403Forbidden, new { error = Messages.Get("scope.outside") });

        var readOnly = criterion != "any";
        var since = days > 0 ? DateTime.UtcNow.AddDays(-days) : DateTime.MinValue;
        var sep = PathText.SeparatorOf(folder);
        var prefix = folder.EndsWith(sep) ? folder : folder + sep;

        // LIKE is case-insensitive in SQLite, as Windows paths are; Linux paths are told apart by
        // the case-sensitive comparer below
        var pattern = prefix.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%";
        var inFolder = _db.AccessRecords.Where(r =>
            r.ServerName == serverName && EF.Functions.Like(r.FilePath, pattern, "\\") && !r.IsFolder && !r.Denied);
        var accessed = inFolder.Where(r => r.AccessTime >= since);
        if (readOnly) accessed = accessed.Where(r => r.AccessType == "Read");
        var used = new HashSet<string>(
            await accessed.Select(r => r.FilePath).Distinct().ToListAsync(ct), PathText.ComparerOf(folder));

        List<ScannedFile> all;
        int scanned;
        bool truncated;
        if (local)
        {
            if (!Directory.Exists(folder))
                return BadRequest(new { error = Messages.Get("path.notFound", folder) });
            var rules = new RecordingRules(RecordingSettings.Load());
            (all, scanned, truncated) = await Task.Run(() => Scan(folder, used, rules, ct), ct);
        }
        else
        {
            if (agent!.Disabled) return BadRequest(new { error = Messages.Get("agents.isDisabled", agent.Name) });
            System.Text.Json.Nodes.JsonObject result;
            try
            {
                result = await _jobs.RunAsync(agent.Id, "scan", new() { ["folder"] = folder }, ScanJobTimeout, ct);
            }
            catch (TimeoutException)
            {
                return StatusCode(StatusCodes.Status504GatewayTimeout, new { error = Messages.Get("agents.noAnswer", agent.Name) });
            }
            if (result["error"]?.GetValue<string>() is { } message)
                return BadRequest(new { error = Messages.Get("agents.jobFailed", agent.Name, message) });
            if (result["exists"]?.GetValue<bool>() != true)
                return BadRequest(new { error = Messages.Get("path.notFound", folder) });
            (all, scanned, truncated) = FromAgentListing(result, used);
        }
        var unused = all.Where(f => !f.Used).ToList();

        // Last access of any type, ever, per file in the folder (for the files and folders shown)
        var lastAccess = await inFolder
            .GroupBy(r => r.FilePath)
            .Select(g => new { Path = g.Key, Last = g.Max(r => r.AccessTime) })
            .ToDictionaryAsync(x => x.Path, x => x.Last, PathText.ComparerOf(folder), ct);

        var recordingSince = await _db.AccessRecords.Where(r => r.ServerName == serverName)
            .MinAsync(r => (DateTime?)r.AccessTime, ct);
        var shown = unused.OrderBy(f => f.Path, StringComparer.OrdinalIgnoreCase).Take(MaxResults).ToList();

        return Ok(new
        {
            folder, days, criterion = readOnly ? "read" : "any", recordingSince,
            scanned, truncated, total = unused.Count, shownCount = shown.Count,
            totalSize = unused.Sum(f => f.Size),
            items = shown.Select(f => new
            {
                path = f.Path, fileName = Path.GetFileName(f.Path), size = f.Size, modified = f.ModifiedUtc,
                lastAccess = lastAccess.TryGetValue(f.Path, out var t) ? t : (DateTime?)null,
            }),
            folders = Summarize(folder, all, lastAccess),
        });
    }

    internal record ScannedFile(string Path, long Size, DateTime ModifiedUtc, bool Used);

    // The agent's "scan" answer: files as [path, size, modified UTC ticks]
    internal static (List<ScannedFile> Files, int Scanned, bool Truncated) FromAgentListing(
        System.Text.Json.Nodes.JsonObject result, HashSet<string> used)
    {
        var files = (result["files"] as System.Text.Json.Nodes.JsonArray ?? [])
            .OfType<System.Text.Json.Nodes.JsonArray>()
            .Select(f =>
            {
                var path = f[0]!.GetValue<string>();
                return new ScannedFile(path, f[1]!.GetValue<long>(),
                    new DateTime(f[2]!.GetValue<long>(), DateTimeKind.Utc), used.Contains(path));
            })
            .ToList();
        return (files, result["scanned"]?.GetValue<int>() ?? files.Count, result["truncated"]?.GetValue<bool>() ?? false);
    }

    internal record FolderSummary(string Path, bool IsSelf, int Files, long Size, int UnusedFiles, long UnusedSize,
        DateTime? LastAccess);

    // Every file in the folder (except excluded ones), marked used when it has a matching record
    internal static (List<ScannedFile> Files, int Scanned, bool Truncated) Scan(
        string folder, HashSet<string> used, RecordingRules rules, CancellationToken ct)
    {
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true };
        var files = new List<ScannedFile>();
        var scanned = 0;
        foreach (var info in new DirectoryInfo(folder).EnumerateFiles("*", options))
        {
            ct.ThrowIfCancellationRequested();
            if (++scanned > MaxScannedFiles) return (files, MaxScannedFiles, true);
            if (rules.IsExcludedFile(info.Name)) continue;
            files.Add(new ScannedFile(info.FullName, info.Length, info.LastWriteTimeUtc, used.Contains(info.FullName)));
        }
        return (files, scanned, false);
    }

    // Totals per subfolder one level below the folder; files directly in it form their own row.
    internal static List<FolderSummary> Summarize(string folder, IEnumerable<ScannedFile> files,
        IReadOnlyDictionary<string, DateTime> lastAccess)
    {
        var sep = PathText.SeparatorOf(folder);
        var prefix = folder.EndsWith(sep) ? folder : folder + sep;
        string KeyOf(string path)
        {
            var rest = path[prefix.Length..];
            var slash = rest.IndexOf(sep);
            return slash < 0 ? "" : prefix + rest[..slash];
        }

        return files
            .GroupBy(f => KeyOf(f.Path), PathText.ComparerOf(folder))
            .Select(g => new FolderSummary(
                g.Key.Length == 0 ? folder : g.Key, g.Key.Length == 0, g.Count(), g.Sum(f => f.Size),
                g.Count(f => !f.Used), g.Where(f => !f.Used).Sum(f => f.Size),
                g.Select(f => lastAccess.TryGetValue(f.Path, out var t) ? t : (DateTime?)null).Max()))
            .OrderByDescending(s => s.UnusedSize)
            .ToList();
    }
}
