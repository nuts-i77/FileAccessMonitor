using System.Text;
using FileAccessMonitor.Controllers;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Services;

// What one report covers. Scope = null: everything (the report for the administrators); a scope:
// only that viewer's folders, and no sections that cannot be limited to folders.
public record ReportRequest(DateTime FromUtc, DateTime ToUtc, DateTime PreviousFromUtc, DateTime FromLocal, DateTime ToLocal,
    string Frequency, string Language, int TopN, bool Csv, IReadOnlyList<ScopeEntry>? Scope);

public record ReportChange(DateTime Time, string User, string Server, string Path);
public record ReportAlertGroup(string Type, int Count, DateTime Last);
public record ReportAlertRow(DateTime Time, string Type, string Server, string User, string Count);
public record ReportTopFile(string Server, string Path, int Total, int Reads, int Writes);
public record ReportTopFolder(string Server, string Folder, int Total);
public record ReportTopUser(string User, int Total, int Reads, int Writes);
public record ReportAgent(string Name, string Os, string Version, DateTime? LastSeen, bool Offline, bool Disabled,
    bool? AuditOk, int Outbox, bool Outdated);
public record ReportPermRoot(string Server, string Root, DateTime ScannedAt, bool Old, int High, int Medium);

public class ReportSummary
{
    public int Total { get; set; }
    public Dictionary<string, int> ByType { get; set; } = [];
    public int UniqueFiles { get; set; }
    public int ActiveUsers { get; set; }
    public int Denied { get; set; }
    public int PermissionChanges { get; set; }
    public int PreviousTotal { get; set; }
    public int PreviousDenied { get; set; }
    public int PreviousPermissionChanges { get; set; }
    public List<ReportChange> Changes { get; set; } = [];   // the newest
}

public class ReportPermissions
{
    public List<ReportPermRoot> Roots { get; set; } = [];
    public List<string> NeverScanned { get; set; } = [];       // "SERVER: folder"
    public int High { get; set; }
    public int Medium { get; set; }
    public List<BroadRow> Top { get; set; } = [];              // the first high rows
    public List<BroadRow> All { get; set; } = [];              // for the CSV
}

public class ReportData
{
    public required ReportRequest Request { get; init; }
    public string ServerLabel { get; init; } = ServerConfigService.LocalName;
    public bool Scoped => Request.Scope != null;
    public ReportSummary Summary { get; set; } = new();
    public List<ReportAlertGroup>? AlertGroups { get; set; }   // null: not in this report
    public List<ReportAlertRow> AlertRows { get; set; } = [];
    public List<ReportTopFile> TopFiles { get; set; } = [];
    public List<ReportTopFolder> TopFolders { get; set; } = [];
    public List<ReportTopUser> TopUsers { get; set; } = [];
    public List<ReportAgent>? Agents { get; set; }             // null: not in this report
    public ReportPermissions? Permissions { get; set; }        // null: could not be read
    public IntegritySummary? Integrity { get; set; }           // null: not in this report or tamper detection is off
}

// A finished mail. Webhook* is the summary for the webhook (no file names), null when there is none.
public record ReportMail(string Subject, string Text, string Html, List<MailAttachmentData> Attachments,
    string? WebhookTitle, string? WebhookText);

// Collects the data of a report from the database, the stored permission scans and the integrity status.
// The permissions come from the last stored scan of each folder: a report never starts a scan.
public class ReportBuilder(IServiceScopeFactory scopeFactory, IPermissionReports permissions, IIntegrityStatus integrity,
    ILogger<ReportBuilder> logger)
{
    public const int MaxCsvRows = 20_000;
    public const int MaxAttachmentBytes = 8 * 1024 * 1024;
    public static readonly TimeSpan OldScan = TimeSpan.FromDays(14);
    private const int ListRows = 20;

    public async Task<ReportData> BuildDataAsync(ReportRequest req, AlertSettings alerts, DateTime nowUtc, CancellationToken ct = default)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var data = new ReportData { Request = req };

        IQueryable<AccessRecord> all = db.AccessRecords.AsNoTracking();
        if (req.Scope != null) all = AccessScope.Apply(all, req.Scope);
        var inPeriod = all.Where(r => r.AccessTime >= req.FromUtc && r.AccessTime < req.ToUtc);
        var ok = inPeriod.Where(r => !r.Denied);
        var before = all.Where(r => r.AccessTime >= req.PreviousFromUtc && r.AccessTime < req.FromUtc);

        // 1. summary (refused attempts are counted apart, as in the statistics)
        var sum = data.Summary;
        sum.Total = await ok.CountAsync(ct);
        sum.ByType = (await ok.GroupBy(r => r.AccessType).Select(g => new { Type = g.Key, Count = g.Count() }).ToListAsync(ct))
            .ToDictionary(x => x.Type, x => x.Count);
        sum.UniqueFiles = await ok.Where(r => !r.IsFolder).Select(r => r.ServerName + ":" + r.FilePath).Distinct().CountAsync(ct);
        sum.ActiveUsers = await ok.Select(r => r.UserName).Distinct().CountAsync(ct);
        sum.Denied = await inPeriod.CountAsync(r => r.Denied, ct);
        sum.PermissionChanges = await ok.CountAsync(r => r.AccessType == "Permission", ct);
        sum.PreviousTotal = await before.CountAsync(r => !r.Denied, ct);
        sum.PreviousDenied = await before.CountAsync(r => r.Denied, ct);
        sum.PreviousPermissionChanges = await before.CountAsync(r => !r.Denied && r.AccessType == "Permission", ct);
        sum.Changes = (await ok.Where(r => r.AccessType == "Permission").OrderByDescending(r => r.AccessTime).ThenByDescending(r => r.Id)
                .Take(ListRows).Select(r => new { r.AccessTime, r.UserName, r.ServerName, r.FilePath }).ToListAsync(ct))
            .Select(r => new ReportChange(Utc(r.AccessTime), r.UserName, r.ServerName, r.FilePath)).ToList();

        // 3. most used files, folders and users
        data.TopFiles = (await ok.Where(r => !r.IsFolder).GroupBy(r => new { r.ServerName, r.FilePath })
                .Select(g => new
                {
                    g.Key.ServerName, g.Key.FilePath, Total = g.Count(),
                    Reads = g.Count(r => r.AccessType == "Read"), Writes = g.Count(r => r.AccessType == "Write"),
                })
                .OrderByDescending(x => x.Total).Take(req.TopN).ToListAsync(ct))
            .Select(x => new ReportTopFile(x.ServerName, x.FilePath, x.Total, x.Reads, x.Writes)).ToList();
        data.TopFolders = (await ok.GroupBy(r => new { r.ServerName, r.FolderPath })
                .Select(g => new { g.Key.ServerName, g.Key.FolderPath, Total = g.Count() })
                .OrderByDescending(x => x.Total).Take(req.TopN).ToListAsync(ct))
            .Select(x => new ReportTopFolder(x.ServerName, x.FolderPath, x.Total)).ToList();
        data.TopUsers = await TopUsersAsync(ok, req.TopN, ct);

        // 5. broad permissions of the last stored scans (everyone's, or inside the scope)
        data.Permissions = await PermissionsAsync(db, req.Scope, nowUtc, ct);

        if (req.Scope == null)
        {
            // 2. alerts sent (they are written to the operation log), 4. agents, 6. integrity
            await AddAlertsAsync(db, data, ct);
            data.Agents = await AgentsAsync(db, alerts, nowUtc, ct);
            try
            {
                var summary = await integrity.GetSummaryAsync(ct);
                data.Integrity = summary.State == "disabled" ? null : summary;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "The integrity status could not be read for the report.");
            }
        }
        return data;
    }

    private static async Task<List<ReportTopUser>> TopUsersAsync(IQueryable<AccessRecord> ok, int take, CancellationToken ct) =>
        (await ok.GroupBy(r => r.UserName)
            .Select(g => new
            {
                User = g.Key, Total = g.Count(),
                Reads = g.Count(r => r.AccessType == "Read"), Writes = g.Count(r => r.AccessType == "Write"),
            })
            .OrderByDescending(x => x.Total).Take(take).ToListAsync(ct))
        .Select(x => new ReportTopUser(x.User, x.Total, x.Reads, x.Writes)).ToList();

    // "type=Ransomware, rule=extension, server=FS01, user=bob, count=20, channels=[email=ok]" -> key/values
    internal static Dictionary<string, string> ParseAlertDetail(string? detail)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(detail)) return map;
        var cut = detail.IndexOf("channels=[", StringComparison.Ordinal);
        foreach (var part in (cut >= 0 ? detail[..cut] : detail).Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq > 0) map[part[..eq].Trim()] = part[(eq + 1)..].Trim();
        }
        return map;
    }

    private async Task AddAlertsAsync(AccessDbContext db, ReportData data, CancellationToken ct)
    {
        var req = data.Request;
        var rows = await db.AuditLogs.AsNoTracking()
            .Where(a => a.Action == "alert.sent" && a.Time >= req.FromUtc && a.Time < req.ToUtc)
            .OrderBy(a => a.Time).Take(5000).Select(a => new { a.Time, a.Detail }).ToListAsync(ct);
        var parsed = rows.Select(r => (Time: Utc(r.Time), Map: ParseAlertDetail(r.Detail))).ToList();
        string TypeOf(Dictionary<string, string> m) =>
            m.GetValueOrDefault("type", "?") + (m.TryGetValue("rule", out var rule) ? $"[{rule}]" : "");
        data.AlertGroups = parsed.GroupBy(p => TypeOf(p.Map))
            .Select(g => new ReportAlertGroup(g.Key, g.Count(), g.Max(p => p.Time)))
            .OrderByDescending(g => g.Count).ToList();
        data.AlertRows = parsed.Where(p => p.Map.GetValueOrDefault("type") is "Ransomware" or "Denied")
            .OrderByDescending(p => p.Time).Take(ListRows)
            .Select(p => new ReportAlertRow(p.Time, TypeOf(p.Map), p.Map.GetValueOrDefault("server", ""),
                p.Map.GetValueOrDefault("user", ""), p.Map.GetValueOrDefault("count", "")))
            .ToList();
    }

    private static async Task<List<ReportAgent>> AgentsAsync(AccessDbContext db, AlertSettings alerts, DateTime nowUtc, CancellationToken ct)
    {
        var offline = TimeSpan.FromMinutes(alerts.AgentOfflineMinutes > 0 ? alerts.AgentOfflineMinutes : 15);
        _ = Version.TryParse(AppInfo.Version, out var server);
        var agents = await db.Agents.AsNoTracking().OrderBy(a => a.Name).ToListAsync(ct);
        return agents.Select(a =>
        {
            var seen = a.LastSeenAt ?? a.CreatedAt;
            var outdated = server != null && Version.TryParse(a.Version, out var v) && v < server;
            return new ReportAgent(a.Name, a.Os ?? "", a.Version ?? "", a.LastSeenAt == null ? null : Utc(a.LastSeenAt.Value),
                !a.Disabled && nowUtc - seen > offline, a.Disabled, a.AuditPolicyOk, a.OutboxCount, outdated);
        }).ToList();
    }

    private async Task<ReportPermissions?> PermissionsAsync(AccessDbContext db, IReadOnlyList<ScopeEntry>? scope, DateTime nowUtc, CancellationToken ct)
    {
        try
        {
            var result = new ReportPermissions();
            var stored = await permissions.ListAsync(ct);
            foreach (var report in stored.OrderBy(r => r.Server).ThenBy(r => r.Root))
            {
                if (scope != null && !Touches(scope, report)) continue;
                var rows = PermissionReportView.BroadRows(report, scope);
                var high = rows.Count(r => r.Severity == "high");
                var medium = rows.Count(r => r.Severity == "medium");
                result.High += high;
                result.Medium += medium;
                result.All.AddRange(rows.Take(MaxCsvRows - result.All.Count));
                result.Roots.Add(new ReportPermRoot(Label(report.Server), report.Root, Utc(report.ScannedAt),
                    nowUtc - report.ScannedAt > OldScan, high, medium));
            }
            result.Top = result.All.Where(r => r.Severity == "high").Take(ListRows).ToList();

            if (scope == null)
            {
                // monitored folders without a stored scan
                var config = new ServerConfigService(db);
                foreach (var server in await config.ServerNamesAsync())
                {
                    foreach (var path in await config.GetPathsAsync(ServerConfigService.IsLocal(server) ? null : server))
                    {
                        var hit = stored.Any(r => (ServerConfigService.IsLocal(r.Server) && ServerConfigService.IsLocal(server)
                                                   || r.Server.Equals(server, StringComparison.OrdinalIgnoreCase))
                                                  && r.Root.Equals(AccessScope.Normalize(path.Path), PathText.ComparisonOf(path.Path)));
                        if (!hit) result.NeverScanned.Add($"{server}: {path.Path}");
                    }
                }
            }
            return result;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "The stored permission scans could not be read for the report.");
            return null;
        }
    }

    // A scan belongs to a scoped report when its folder and the viewer's folders overlap
    private static bool Touches(IReadOnlyList<ScopeEntry> scope, StoredPermissionReport report) =>
        AccessScope.Contains(scope, Label(report.Server), report.Root)
        || scope.Any(e => (e.Server == null || e.Server.Equals(Label(report.Server), StringComparison.OrdinalIgnoreCase))
                          && PathText.IsUnder(e.Path, report.Root));

    private static string Label(string server) => string.IsNullOrEmpty(server) ? ServerConfigService.LocalName : server;

    private static DateTime Utc(DateTime t) => DateTime.SpecifyKind(t, DateTimeKind.Utc);

    // ---- the finished mail

    public async Task<ReportMail> BuildMailAsync(ReportRequest req, AlertSettings alerts, DateTime nowUtc, bool test, CancellationToken ct = default)
    {
        var data = await BuildDataAsync(req, alerts, nowUtc, ct);
        var attachments = new List<MailAttachmentData>();
        var dropped = new List<string>();
        var cut = false;
        if (req.Csv)
        {
            (attachments, cut) = await BuildAttachmentsAsync(data, ct);
            attachments = ReportAttachments.Fit(attachments, MaxAttachmentBytes, dropped);
        }
        var (html, text) = ReportHtml.Render(data, dropped, cut);
        var prefix = test ? Messages.GetIn(req.Language, "report.testPrefix") + " " : "";
        var subject = prefix + ReportHtml.Subject(data);
        // the webhook gets numbers only; a scoped viewer's report goes by mail only
        var webhook = data.Scoped ? null : ReportHtml.WebhookText(data);
        return new ReportMail(subject, text, html, attachments, webhook == null ? null : subject, webhook);
    }

    // Row-level files for the CSV attachments; the bool says that a file was cut at MaxCsvRows
    private async Task<(List<MailAttachmentData>, bool)> BuildAttachmentsAsync(ReportData data, CancellationToken ct)
    {
        var req = data.Request;
        string L(string key) => Messages.GetIn(req.Language, key);
        var tz = TimeZoneInfo.Local;
        string Local(DateTime utc) => TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(utc, DateTimeKind.Utc), tz).ToString("yyyy-MM-dd HH:mm:ss");
        string UtcText(DateTime utc) => DateTime.SpecifyKind(utc, DateTimeKind.Utc).ToString("yyyy-MM-ddTHH:mm:ssZ");
        var timeHeader = L("report.csv.time");

        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        IQueryable<AccessRecord> all = db.AccessRecords.AsNoTracking();
        if (req.Scope != null) all = AccessScope.Apply(all, req.Scope);
        var inPeriod = all.Where(r => r.AccessTime >= req.FromUtc && r.AccessTime < req.ToUtc);

        var files = new List<MailAttachmentData>();
        var cut = false;
        void Add(string name, string[] header, IEnumerable<string?[]> rows)
        {
            var (file, truncated) = ReportAttachments.Csv(name, header, rows);
            cut |= truncated;
            files.Add(file);
        }

        if (data.Permissions is { All.Count: > 0 } perm)
            Add("broad-permissions.csv",
                [L("report.csv.server"), L("report.csv.folder"), L("report.csv.path"), L("report.csv.principal"), L("report.csv.kind"),
                 L("report.csv.level"), L("report.csv.severity"), L("report.csv.broken")],
                perm.All.Select(r => new string?[] { r.Server, r.Root, r.Path, r.Principal, r.Kind, r.Level, r.Severity,
                    r.InheritanceBroken ? L("report.yes") : "" }));

        var changes = await inPeriod.Where(r => !r.Denied && r.AccessType == "Permission").OrderBy(r => r.AccessTime)
            .Take(MaxCsvRows + 1).Select(r => new { r.AccessTime, r.UserName, r.ServerName, r.FilePath, r.Detail }).ToListAsync(ct);
        if (changes.Count > 0)
            Add("permission-changes.csv",
                [$"{timeHeader} ({tz.BaseUtcOffset:hh\\:mm})", L("report.csv.timeUtc"), L("report.csv.user"), L("report.csv.server"), L("report.csv.path"), L("report.csv.detail")],
                changes.Select(r => new string?[] { Local(r.AccessTime), UtcText(r.AccessTime), r.UserName, r.ServerName, r.FilePath, r.Detail }));

        var denied = await inPeriod.Where(r => r.Denied).OrderBy(r => r.AccessTime).Take(MaxCsvRows + 1)
            .Select(r => new { r.AccessTime, r.UserName, r.AccessType, r.ServerName, r.FilePath, r.ClientIp, r.ClientMachine }).ToListAsync(ct);
        if (denied.Count > 0)
            Add("denied.csv",
                [timeHeader, L("report.csv.timeUtc"), L("report.csv.user"), L("report.csv.type"), L("report.csv.server"), L("report.csv.path"),
                 L("report.csv.ip"), L("report.csv.machine")],
                denied.Select(r => new string?[] { Local(r.AccessTime), UtcText(r.AccessTime), r.UserName, r.AccessType, r.ServerName, r.FilePath, r.ClientIp, r.ClientMachine }));

        var ok = inPeriod.Where(r => !r.Denied);
        var topFiles = await ok.Where(r => !r.IsFolder).GroupBy(r => new { r.ServerName, r.FilePath })
            .Select(g => new
            {
                g.Key.ServerName, g.Key.FilePath, Total = g.Count(),
                Reads = g.Count(r => r.AccessType == "Read"), Writes = g.Count(r => r.AccessType == "Write"),
            })
            .OrderByDescending(x => x.Total).Take(1000).ToListAsync(ct);
        if (topFiles.Count > 0)
            Add("top-files.csv", [L("report.csv.server"), L("report.csv.path"), L("report.csv.total"), L("report.csv.reads"), L("report.csv.writes")],
                topFiles.Select(f => new string?[] { f.ServerName, f.FilePath, f.Total.ToString(), f.Reads.ToString(), f.Writes.ToString() }));

        var topUsers = await TopUsersAsync(ok, 1000, ct);
        if (topUsers.Count > 0)
            Add("top-users.csv", [L("report.csv.user"), L("report.csv.total"), L("report.csv.reads"), L("report.csv.writes")],
                topUsers.Select(u => new string?[] { u.User, u.Total.ToString(), u.Reads.ToString(), u.Writes.ToString() }));
        return (files, cut);
    }
}

// CSV files for the mail: UTF-8 with BOM, values that Excel would run as a formula are neutralized
public static class ReportAttachments
{
    public static (MailAttachmentData File, bool Truncated) Csv(string name, string[] header, IEnumerable<string?[]> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine(StatsController.CsvLine(header));
        var count = 0;
        var truncated = false;
        foreach (var row in rows)
        {
            if (count == ReportBuilder.MaxCsvRows)
            {
                truncated = true;
                break;
            }
            sb.AppendLine(StatsController.CsvLine(row));
            count++;
        }
        var bytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: true).GetPreamble()
            .Concat(Encoding.UTF8.GetBytes(sb.ToString())).ToArray();
        return (new MailAttachmentData(name, bytes, "text/csv; charset=utf-8"), truncated);
    }

    // Drops the largest files until the rest fits; their names go to `dropped`
    public static List<MailAttachmentData> Fit(List<MailAttachmentData> files, int maxBytes, List<string> dropped)
    {
        var kept = files.ToList();
        while (kept.Sum(f => (long)f.Content.Length) > maxBytes && kept.Count > 0)
        {
            var biggest = kept.MaxBy(f => f.Content.Length)!;
            kept.Remove(biggest);
            dropped.Add(biggest.FileName);
        }
        return kept;
    }
}
