using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace FileAccessMonitor.Services;

// Stored permission scans: the GUI reads them, the scheduled report uses the last one of each folder
public interface IPermissionReports
{
    // The last stored scan of (server, root), or null. Never starts a scan.
    Task<StoredPermissionReport?> GetLastAsync(string server, string root, CancellationToken ct = default);
    Task<List<StoredPermissionReport>> ListAsync(CancellationToken ct = default);
    Task<StoredPermissionReport> ScanAsync(string server, string root, PermissionScanOptions options, CancellationToken ct);
}

// Server = the file server's name ("" = this machine); Result = the job result (see PermissionContract)
public class StoredPermissionReport
{
    public string Server { get; set; } = "";
    public string Root { get; set; } = "";
    public DateTime ScannedAt { get; set; }
    public string Os { get; set; } = "";
    public string? AgentVersion { get; set; }
    public JsonObject Result { get; set; } = [];
}

// A broad-access entry. Severity: high | medium
public record BroadRow(string Server, string Root, string Path, string Principal, string Kind,
    string Level, string Severity, bool InheritanceBroken);

// A scan that cannot run or has no answer; Status is the HTTP status the API answers with
public class PermissionScanException(int status, string message) : Exception(message)
{
    public int Status { get; } = status;
}

// One entry of a stored row, with its classification
public record ViewAce(string Principal, string? Sid, string Kind, int Level, string LevelLabel, int Scope,
    string ScopeLabel, int? LevelBeforeMask, string? Broad, string? Severity);

// One folder or file of a stored scan; Path is absolute
public record ViewRow(string Rel, string Path, int Depth, int Flags, string? Owner, List<ViewAce> Aces, string Severity)
{
    public bool IsFolder => (Flags & PermissionContract.FlagFolder) != 0;
    public bool InheritanceBroken => (Flags & PermissionContract.FlagInheritanceBroken) != 0;
    public bool NotReadable => (Flags & PermissionContract.FlagNotReadable) != 0;
}

public record ViewShare(string Name, string Path, bool GuestOk, bool ReadOnly, string ValidUsers, string WriteList,
    bool NtAcl, string? Severity);

public static class PermissionReportView
{
    // Extra names to treat as broad: settings.json -> Permissions:BroadPrincipals
    public static List<string> ExtraBroadPrincipals()
    {
        try
        {
            return (SettingsStore.Load()["Permissions"]?["BroadPrincipals"] as JsonArray ?? [])
                .Select(n => n?.GetValue<string>() ?? "").Where(s => s.Length > 0).ToList();
        }
        catch (Exception) { return []; }
    }

    // Broad-access rows of a scan; scope = null (everything) or the viewer's folders
    public static List<BroadRow> BroadRows(StoredPermissionReport report, IReadOnlyList<ScopeEntry>? scope)
    {
        var extra = ExtraBroadPrincipals();
        var rows = new List<BroadRow>();
        foreach (var row in Rows(report, extra))
        {
            if (scope != null && !AccessScope.Contains(scope, report.Server, row.Path)) continue;
            foreach (var a in row.Aces.Where(a => a.Severity != null))
                rows.Add(new BroadRow(report.Server, report.Root, row.Path, a.Principal, a.Broad!, a.LevelLabel,
                    a.Severity!, row.InheritanceBroken));
        }
        if (scope == null || AccessScope.Contains(scope, report.Server, report.Root))
            foreach (var s in Shares(report).Where(s => s.Severity != null))
                rows.Add(new BroadRow(report.Server, report.Root, s.Path, "share:" + s.Name, "guestShare",
                    s.ReadOnly ? "Read" : "Read/Write", s.Severity!, false));
        return rows;
    }

    // The rows of a stored scan, entries classified
    public static List<ViewRow> Rows(StoredPermissionReport report, IReadOnlyCollection<string>? extra = null)
    {
        var principals = (report.Result["principals"] as JsonArray ?? [])
            .Select(p => (Name: p?[0]?.GetValue<string>() ?? "", Sid: p?[1]?.GetValue<string>())).ToList();
        string? NameOf(int i) => i >= 0 && i < principals.Count ? principals[i].Name : null;
        var sep = PathText.SeparatorOf(report.Root);
        var rows = new List<ViewRow>();
        foreach (var node in report.Result["rows"] as JsonArray ?? [])
        {
            if (node is not JsonArray r || r.Count < 4) continue;
            var rel = r[0]?.GetValue<string>() ?? "";
            var flags = r[1]?.GetValue<int>() ?? 0;
            var aces = new List<ViewAce>();
            var severity = "";
            foreach (var an in r[3] as JsonArray ?? [])
            {
                if (an is not JsonArray a || a.Count < 4) continue;
                var idx = a[0]!.GetValue<int>();
                if (idx < 0 || idx >= principals.Count) continue;
                var (name, sid) = principals[idx];
                var deny = a[1]!.GetValue<int>() == 1;
                var level = a[2]!.GetValue<int>();
                var scope = a[3]!.GetValue<int>();
                var broad = PermissionAnalysis.BroadKind(name, sid, extra);
                var sev = PermissionAnalysis.Severity(broad, level, deny);
                severity = PermissionAnalysis.MaxSeverity(severity, sev);
                aces.Add(new ViewAce(name, sid, deny ? "deny" : "allow", level, PermissionContract.LevelLabel(level), scope,
                    PermissionContract.ScopeLabel(scope), a.Count > 4 ? a[4]!.GetValue<int>() : null, broad, sev));
            }
            var depth = rel.Length == 0 ? 0 : rel.Count(c => c == sep) + 1;
            rows.Add(new ViewRow(rel, PermissionContract.Absolute(report.Root, rel), depth, flags,
                NameOf(r[2]?.GetValue<int>() ?? -1), aces, severity));
        }
        return rows;
    }

    public static List<ViewShare> Shares(StoredPermissionReport report) =>
        (report.Result["shares"] as JsonArray ?? []).OfType<JsonObject>().Select(s =>
        {
            var guest = s["guestOk"]?.GetValue<bool>() ?? false;
            var readOnly = s["readOnly"]?.GetValue<bool>() ?? true;
            return new ViewShare(s["name"]?.GetValue<string>() ?? "", s["path"]?.GetValue<string>() ?? "", guest, readOnly,
                s["validUsers"]?.GetValue<string>() ?? "", s["writeList"]?.GetValue<string>() ?? "",
                s["ntAcl"]?.GetValue<bool>() ?? false, PermissionAnalysis.ShareSeverity(guest, readOnly));
        }).ToList();

    // Folders before files, children right after their parent, names compared the way the OS does
    public static IComparer<ViewRow> TreeOrder(string root)
    {
        var sep = PathText.SeparatorOf(root);
        var comparer = PathText.ComparerOf(root);
        return Comparer<ViewRow>.Create((a, b) =>
        {
            var x = a.Rel.Split(sep);
            var y = b.Rel.Split(sep);
            for (var i = 0; i < Math.Min(x.Length, y.Length); i++)
            {
                var xFile = i == x.Length - 1 && !a.IsFolder;
                var yFile = i == y.Length - 1 && !b.IsFolder;
                if (xFile != yFile) return xFile ? 1 : -1;
                var c = comparer.Compare(x[i], y[i]);
                if (c != 0) return c;
            }
            return x.Length.CompareTo(y.Length);
        });
    }
}

// Runs permission scans (here for this machine, through the agent for another server) and keeps the
// last result of each (server, folder) in <data dir>/permission-reports.
public class PermissionReportService : IPermissionReports
{
    // Agents older than this do not know the "permissions" job
    public static readonly Version AgentMinVersion = new(1, 10);

    private readonly string _dir;
    private readonly IServiceScopeFactory _scopes;
    private readonly AgentJobs _jobs;
    private readonly ILogger<PermissionReportService> _logger;
    private readonly ConcurrentDictionary<string, byte> _running = new();

    public PermissionReportService(IServiceScopeFactory scopes, AgentJobs jobs, ILogger<PermissionReportService> logger)
        : this(Path.Combine(AppPaths.DataDir, "permission-reports"), scopes, jobs, logger) { }

    internal PermissionReportService(string directory, IServiceScopeFactory scopes, AgentJobs jobs, ILogger<PermissionReportService> logger)
    {
        _dir = directory;
        _scopes = scopes;
        _jobs = jobs;
        _logger = logger;
    }

    public static string CanonicalServer(string? server) =>
        ServerConfigService.IsLocal(server) ? ServerConfigService.LocalName : server!.Trim();

    public async Task<StoredPermissionReport?> GetLastAsync(string server, string root, CancellationToken ct = default)
    {
        var file = FileOf(CanonicalServer(server), PathText.Normalize(root));
        return await ReadAsync(file, ct);
    }

    // Removes the stored scan of (server, root); false when there was none
    public bool Delete(string server, string root)
    {
        var file = FileOf(CanonicalServer(server), PathText.Normalize(root));
        if (!File.Exists(file)) return false;
        File.Delete(file);
        return true;
    }

    public async Task<List<StoredPermissionReport>> ListAsync(CancellationToken ct = default)
    {
        var list = new List<StoredPermissionReport>();
        if (!Directory.Exists(_dir)) return list;
        foreach (var file in Directory.EnumerateFiles(_dir, "*.json"))
            if (await ReadAsync(file, ct) is { } report) list.Add(report);
        return list.OrderBy(r => r.Server, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.Root, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task<StoredPermissionReport> ScanAsync(string server, string root, PermissionScanOptions options, CancellationToken ct)
    {
        var local = ServerConfigService.IsLocal(server);
        server = CanonicalServer(server);
        root = PathText.Normalize(root);
        var o = PermissionContract.Clamp(options);

        // One scan of a folder at a time; a second request is told so
        var key = server.ToUpperInvariant() + "|" + RootKey(root);
        if (!_running.TryAdd(key, 0)) throw new PermissionScanException(409, Messages.Get("perm.running"));
        try
        {
            string? agentVersion = null;
            JsonObject result;
            if (local)
            {
                if (!ServerConfigService.LocalCollects) throw new PermissionScanException(400, Messages.Get("local.notCollecting"));
                result = await ScanOnCollectorAsync(root, o, ct);
            }
            else
            {
                (result, agentVersion) = await ScanOnAgentAsync(server, root, o, ct);
            }
            // Kept with the result so the GUI can say whether files were looked at
            result["includeFiles"] = o.IncludeFiles;
            var report = new StoredPermissionReport
            {
                Server = server, Root = root, Os = result["os"]?.GetValue<string>() ?? "", AgentVersion = agentVersion,
                ScannedAt = DateTime.TryParse(result["scannedAt"]?.GetValue<string>(), null,
                    System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var at)
                    ? at : DateTime.UtcNow,
                Result = result,
            };
            await WriteAsync(report, ct);
            return report;
        }
        finally
        {
            _running.TryRemove(key, out _);
        }
    }

    // This machine's folders are read by the collector service (the web service runs without privileges and
    // may not be allowed to read the shares or their ACLs), as a job like on an agent
    private async Task<JsonObject> ScanOnCollectorAsync(string root, PermissionScanOptions o, CancellationToken ct)
    {
        using var scope = _scopes.CreateScope();
        var collector = scope.ServiceProvider.GetRequiredService<LocalCollectorState>();
        JsonObject result;
        try
        {
            result = await collector.RunJobAsync(_jobs, PermissionContract.JobType, PermissionContract.ToArgs(root, o),
                TimeSpan.FromSeconds(o.TimeLimitSeconds + 60), ct);
        }
        catch (LocalCollectorException ex)
        {
            throw new PermissionScanException(ex.Status, ex.Message);
        }
        if (result["exists"]?.GetValue<bool>() != true)
            throw new PermissionScanException(400, Messages.Get("path.notFound", root));
        return result;
    }

    private async Task<(JsonObject Result, string? Version)> ScanOnAgentAsync(string server, string root, PermissionScanOptions o,
        CancellationToken ct)
    {
        using var scope = _scopes.CreateScope();
        var servers = scope.ServiceProvider.GetRequiredService<ServerConfigService>();
        var agent = await servers.FindAgentAsync(server) ?? throw new PermissionScanException(404, Messages.Get("agents.notFound"));
        if (agent.Disabled) throw new PermissionScanException(400, Messages.Get("agents.isDisabled", agent.Name));
        if (IsTooOld(agent.Version)) throw new PermissionScanException(409, Messages.Get("perm.agentTooOld", agent.Name, agent.Version ?? "?"));

        JsonObject result;
        try
        {
            result = await _jobs.RunAsync(agent.Id, PermissionContract.JobType, PermissionContract.ToArgs(root, o),
                TimeSpan.FromSeconds(o.TimeLimitSeconds + 60), ct);
        }
        catch (TimeoutException)
        {
            throw new PermissionScanException(504, Messages.Get("agents.noAnswer", agent.Name));
        }
        if (result["error"]?.GetValue<string>() is { } message)
        {
            // An agent of a build that does not know the job
            if (message.StartsWith("Unknown job", StringComparison.Ordinal))
                throw new PermissionScanException(409, Messages.Get("perm.agentTooOld", agent.Name, agent.Version ?? "?"));
            throw new PermissionScanException(400, Messages.Get("agents.jobFailed", agent.Name, message));
        }
        if (result["exists"]?.GetValue<bool>() != true)
            throw new PermissionScanException(400, Messages.Get("path.notFound", root));
        _logger.LogInformation("Permission scan of {Root} on {Server}: {Folders} folders, {Files} files.",
            root, server, result["folders"], result["files"]);
        return (result, agent.Version);
    }

    // A version below 1.10 (or 1.10 pre-releases are fine: only the numbers count). An agent that
    // never told its version gets the job; the "Unknown job" answer covers it.
    internal static bool IsTooOld(string? version)
    {
        if (string.IsNullOrWhiteSpace(version)) return false;
        return Version.TryParse(version.Split('+', '-')[0], out var v) && v < AgentMinVersion;
    }

    // ── Store ─────────────────────────────────────────────────────

    // Windows paths do not differ by case, Linux paths do
    private static string RootKey(string root) => PathText.IsUnix(root) ? root : root.ToUpperInvariant();

    private string FileOf(string server, string root)
    {
        var safeServer = string.Concat(server.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '_'));
        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(RootKey(root)))).ToLowerInvariant();
        return Path.Combine(_dir, $"{safeServer.ToLowerInvariant()}__{hash}.json");
    }

    internal async Task WriteAsync(StoredPermissionReport report, CancellationToken ct)
    {
        Directory.CreateDirectory(_dir);
        var file = FileOf(report.Server, report.Root);
        var node = new JsonObject
        {
            ["server"] = report.Server, ["root"] = report.Root, ["scannedAt"] = report.ScannedAt.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["os"] = report.Os, ["agentVersion"] = report.AgentVersion, ["result"] = report.Result.DeepClone(),
        };
        // A temporary file and a move, so a reader never sees half a file
        var temp = file + "." + Guid.NewGuid().ToString("N") + ".tmp";
        await File.WriteAllTextAsync(temp, node.ToJsonString(), new UTF8Encoding(false), ct);
        File.Move(temp, file, overwrite: true);
    }

    private async Task<StoredPermissionReport?> ReadAsync(string file, CancellationToken ct)
    {
        if (!File.Exists(file)) return null;
        try
        {
            var node = JsonNode.Parse(await File.ReadAllTextAsync(file, ct))?.AsObject();
            if (node?["result"] is not JsonObject result) return null;
            return new StoredPermissionReport
            {
                Server = node["server"]?.GetValue<string>() ?? "", Root = node["root"]?.GetValue<string>() ?? "",
                ScannedAt = DateTime.SpecifyKind(DateTime.Parse(node["scannedAt"]!.GetValue<string>(), null,
                    System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal), DateTimeKind.Utc),
                Os = node["os"]?.GetValue<string>() ?? "", AgentVersion = node["agentVersion"]?.GetValue<string>(), Result = result,
            };
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException or FormatException or InvalidOperationException)
        {
            _logger.LogWarning(ex, "Could not read the stored permission scan {File}.", file);
            return null;
        }
    }
}
