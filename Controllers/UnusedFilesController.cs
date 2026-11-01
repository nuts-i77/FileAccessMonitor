using FileAccessMonitor.Data;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Controllers;

// Files in a monitored folder that nobody read (or accessed at all) in a period. The folder is
// scanned on disk, because files that were never accessed have no records. Admin only, since it
// lists file names that the access records do not contain.
[ApiController]
[Route("api/unused-files")]
[Authorize(Roles = "Admin")]
public class UnusedFilesController : ControllerBase
{
    internal const int MaxScannedFiles = 100_000;
    private const int MaxResults = 2_000;

    private readonly AccessDbContext _db;

    public UnusedFilesController(AccessDbContext db) => _db = db;

    // GET /api/unused-files?folder=D:\Share\Video&days=90&criterion=read
    // days = 0: since the first record; criterion = read (not read) | any (not accessed at all)
    [HttpGet]
    public async Task<IActionResult> Get([FromQuery] string folder, [FromQuery] int days = 90,
        [FromQuery] string criterion = "read", CancellationToken ct = default)
    {
        folder = (folder ?? "").Trim().TrimEnd('\\');
        if (folder.Length == 0)
            return BadRequest(new { error = Messages.Get("path.required") });
        if (folder.EndsWith(':')) folder += "\\";

        var (configs, _) = SettingsController.ReadSettingsDoc();
        if (!configs.Any(c => EventLogCollectorService.IsUnderPath(folder, c.Path)))
            return BadRequest(new { error = Messages.Get("path.notMonitored") });
        if (!Directory.Exists(folder))
            return BadRequest(new { error = Messages.Get("path.notFound", folder) });

        var readOnly = criterion != "any";
        var since = days > 0 ? DateTime.UtcNow.AddDays(-days) : DateTime.MinValue;
        var prefix = folder.EndsWith('\\') ? folder : folder + "\\";

        // LIKE is case-insensitive in SQLite, as Windows paths are
        var pattern = prefix.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%";
        var accessed = _db.AccessRecords.Where(r =>
            EF.Functions.Like(r.FilePath, pattern, "\\") && r.AccessTime >= since && !r.IsFolder);
        if (readOnly) accessed = accessed.Where(r => r.AccessType == "Read");
        var used = new HashSet<string>(
            await accessed.Select(r => r.FilePath).Distinct().ToListAsync(ct), StringComparer.OrdinalIgnoreCase);

        var rules = new RecordingRules(RecordingSettings.Load());
        var (all, scanned, truncated) = await Task.Run(() => Scan(folder, used, rules, ct), ct);
        var unused = all.Where(f => !f.Used).ToList();

        // Last access of any type, ever, per file in the folder (for the files and folders shown)
        var lastAccess = await _db.AccessRecords
            .Where(r => EF.Functions.Like(r.FilePath, pattern, "\\") && !r.IsFolder)
            .GroupBy(r => r.FilePath)
            .Select(g => new { Path = g.Key, Last = g.Max(r => r.AccessTime) })
            .ToDictionaryAsync(x => x.Path, x => x.Last, StringComparer.OrdinalIgnoreCase, ct);

        var recordingSince = await _db.AccessRecords.MinAsync(r => (DateTime?)r.AccessTime, ct);
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
        var prefix = folder.EndsWith('\\') ? folder : folder + "\\";
        string KeyOf(string path)
        {
            var rest = path[prefix.Length..];
            var slash = rest.IndexOf('\\');
            return slash < 0 ? "" : prefix + rest[..slash];
        }

        return files
            .GroupBy(f => KeyOf(f.Path), StringComparer.OrdinalIgnoreCase)
            .Select(g => new FolderSummary(
                g.Key.Length == 0 ? folder : g.Key, g.Key.Length == 0, g.Count(), g.Sum(f => f.Size),
                g.Count(f => !f.Used), g.Where(f => !f.Used).Sum(f => f.Size),
                g.Select(f => lastAccess.TryGetValue(f.Path, out var t) ? t : (DateTime?)null).Max()))
            .OrderByDescending(s => s.UnusedSize)
            .ToList();
    }
}
