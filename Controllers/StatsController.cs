using FileAccessMonitor.Data;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Controllers;

[ApiController]
[Route("api/[controller]")]
[Microsoft.AspNetCore.Authorization.Authorize]
public class StatsController : ControllerBase
{
    private readonly AccessDbContext _db;
    private readonly AuditLog _audit;

    public StatsController(AccessDbContext db, AuditLog audit)
    {
        _db = db;
        _audit = audit;
    }

    // GET /api/stats/summary?days=7
    [HttpGet("summary")]
    public async Task<IActionResult> Summary([FromQuery] int days = 7)
    {
        var since = DateTime.UtcNow.AddDays(-days);
        var q = _db.AccessRecords.Where(r => r.AccessTime >= since);

        var total = await q.CountAsync();
        var uniqueFiles = await q.Select(r => r.FilePath).Distinct().CountAsync();
        var uniqueUsers = await q.Select(r => r.UserName).Distinct().CountAsync();
        var byType = await q.GroupBy(r => r.AccessType)
            .Select(g => new { Type = g.Key, Count = g.Count() })
            .ToListAsync();

        return Ok(new { total, uniqueFiles, uniqueUsers, byType });
    }

    // GET /api/stats/top-files?limit=20&days=7&accessType=
    [HttpGet("top-files")]
    public async Task<IActionResult> TopFiles(
        [FromQuery] int limit = 20,
        [FromQuery] int days = 7,
        [FromQuery] string? accessType = null)
    {
        var since = DateTime.UtcNow.AddDays(-days);
        var q = _db.AccessRecords.Where(r => r.AccessTime >= since);
        if (!string.IsNullOrEmpty(accessType))
            q = q.Where(r => r.AccessType == accessType);

        var result = await q
            .GroupBy(r => new { r.FilePath, r.FileName })
            .Select(g => new
            {
                g.Key.FilePath,
                g.Key.FileName,
                Total = g.Count(),
                Read = g.Count(r => r.AccessType == "Read"),
                Write = g.Count(r => r.AccessType == "Write"),
                Delete = g.Count(r => r.AccessType == "Delete"),
                LastAccess = g.Max(r => r.AccessTime),
                TopUser = g.GroupBy(r => r.UserName)
                           .OrderByDescending(u => u.Count())
                           .Select(u => u.Key)
                           .FirstOrDefault()
            })
            .OrderByDescending(x => x.Total)
            .Take(limit)
            .ToListAsync();

        return Ok(result);
    }

    // GET /api/stats/top-folders?limit=20&days=7
    [HttpGet("top-folders")]
    public async Task<IActionResult> TopFolders(
        [FromQuery] int limit = 20,
        [FromQuery] int days = 7,
        [FromQuery] string? accessType = null)
    {
        var since = DateTime.UtcNow.AddDays(-days);
        var q = _db.AccessRecords.Where(r => r.AccessTime >= since);
        if (!string.IsNullOrEmpty(accessType))
            q = q.Where(r => r.AccessType == accessType);

        var result = await q
            .GroupBy(r => r.FolderPath)
            .Select(g => new
            {
                FolderPath = g.Key,
                FolderName = g.Key.Length > 0
                    ? EF.Functions.Like(g.Key, @"%\%")
                        ? g.Key.Substring(g.Key.LastIndexOf('\\') + 1)
                        : g.Key
                    : g.Key,
                Total = g.Count(),
                Read = g.Count(r => r.AccessType == "Read"),
                Write = g.Count(r => r.AccessType == "Write"),
                Delete = g.Count(r => r.AccessType == "Delete"),
                UniqueFiles = g.Select(r => r.FilePath).Distinct().Count(),
                LastAccess = g.Max(r => r.AccessTime)
            })
            .OrderByDescending(x => x.Total)
            .Take(limit)
            .ToListAsync();

        return Ok(result);
    }

    // GET /api/stats/file-detail?path=...&days=7
    [HttpGet("file-detail")]
    public async Task<IActionResult> FileDetail(
        [FromQuery] string path,
        [FromQuery] int days = 30)
    {
        var since = DateTime.UtcNow.AddDays(-days);
        var q = _db.AccessRecords.Where(r => r.FilePath == path && r.AccessTime >= since);

        var byUser = await q.GroupBy(r => r.UserName)
            .Select(g => new { User = g.Key, Count = g.Count() })
            .OrderByDescending(x => x.Count)
            .ToListAsync();

        var byType = await q.GroupBy(r => r.AccessType)
            .Select(g => new { Type = g.Key, Count = g.Count() })
            .ToListAsync();

        var timeline = await HourlyTimeline(q);

        var recent = await q
            .OrderByDescending(r => r.AccessTime)
            .Take(50)
            .Select(r => new { r.AccessTime, r.UserName, r.AccessType })
            .ToListAsync();

        return Ok(new { path, byUser, byType, timeline, recent });
    }

    // GET /api/stats/folder-detail?path=...&days=7
    [HttpGet("folder-detail")]
    public async Task<IActionResult> FolderDetail(
        [FromQuery] string path,
        [FromQuery] int days = 30)
    {
        var since = DateTime.UtcNow.AddDays(-days);
        var q = _db.AccessRecords.Where(r =>
            r.FolderPath == path && r.AccessTime >= since);

        var byUser = await q.GroupBy(r => r.UserName)
            .Select(g => new { User = g.Key, Count = g.Count() })
            .OrderByDescending(x => x.Count)
            .ToListAsync();

        var byType = await q.GroupBy(r => r.AccessType)
            .Select(g => new { Type = g.Key, Count = g.Count() })
            .ToListAsync();

        var timeline = await HourlyTimeline(q);

        var topFiles = await q
            .GroupBy(r => new { r.FilePath, r.FileName })
            .Select(g => new
            {
                g.Key.FilePath,
                g.Key.FileName,
                Count = g.Count()
            })
            .OrderByDescending(x => x.Count)
            .Take(20)
            .ToListAsync();

        return Ok(new { path, byUser, byType, timeline, topFiles });
    }

    // GET /api/stats/timeline?days=30
    [HttpGet("timeline")]
    public async Task<IActionResult> Timeline([FromQuery] int days = 30)
    {
        var since = DateTime.UtcNow.AddDays(-days);

        var rows = await _db.AccessRecords
            .Where(r => r.AccessTime >= since)
            .GroupBy(r => new { r.AccessTime.Date, r.AccessTime.Hour, r.AccessType })
            .Select(g => new { g.Key.Date, g.Key.Hour, g.Key.AccessType, Count = g.Count() })
            .ToListAsync();

        var result = rows
            .Select(x => new { Date = UtcHour(x.Date, x.Hour), x.AccessType, x.Count })
            .OrderBy(x => x.Date);

        return Ok(result);
    }

    // Timelines are bucketed by UTC hour (serialized with "Z") so the browser
    // can regroup them into days of the viewer's local time zone.
    private static async Task<List<TimelinePoint>> HourlyTimeline(IQueryable<Models.AccessRecord> q)
    {
        var rows = await q
            .GroupBy(r => new { r.AccessTime.Date, r.AccessTime.Hour })
            .Select(g => new { g.Key.Date, g.Key.Hour, Count = g.Count() })
            .ToListAsync();

        return rows
            .Select(x => new TimelinePoint(UtcHour(x.Date, x.Hour), x.Count))
            .OrderBy(x => x.Date)
            .ToList();
    }

    private static DateTime UtcHour(DateTime date, int hour) =>
        DateTime.SpecifyKind(date.AddHours(hour), DateTimeKind.Utc);

    private record TimelinePoint(DateTime Date, int Count);

    // GET /api/stats/top-users?limit=10&days=7
    [HttpGet("top-users")]
    public async Task<IActionResult> TopUsers(
        [FromQuery] int limit = 10,
        [FromQuery] int days = 7)
    {
        var since = DateTime.UtcNow.AddDays(-days);

        var result = await _db.AccessRecords
            .Where(r => r.AccessTime >= since)
            .GroupBy(r => r.UserName)
            .Select(g => new
            {
                User = g.Key,
                Total = g.Count(),
                Read = g.Count(r => r.AccessType == "Read"),
                Write = g.Count(r => r.AccessType == "Write"),
                Delete = g.Count(r => r.AccessType == "Delete")
            })
            .OrderByDescending(x => x.Total)
            .Take(limit)
            .ToListAsync();

        return Ok(result);
    }

    // GET /api/stats/user-detail?user=XXX&days=30
    [HttpGet("user-detail")]
    public async Task<IActionResult> UserDetail(
        [FromQuery] string user,
        [FromQuery] int days = 30)
    {
        var since = DateTime.UtcNow.AddDays(-days);
        var q = _db.AccessRecords.Where(r => r.UserName == user && r.AccessTime >= since);

        var byType = await q.GroupBy(r => r.AccessType)
            .Select(g => new { Type = g.Key, Count = g.Count() })
            .ToListAsync();

        var topFiles = await q
            .GroupBy(r => new { r.FilePath, r.FileName })
            .Select(g => new
            {
                g.Key.FilePath,
                g.Key.FileName,
                Total = g.Count(),
                Read = g.Count(r => r.AccessType == "Read"),
                Write = g.Count(r => r.AccessType == "Write"),
                Delete = g.Count(r => r.AccessType == "Delete"),
                LastAccess = g.Max(r => r.AccessTime)
            })
            .OrderByDescending(x => x.Total)
            .Take(100)
            .ToListAsync();

        var timeline = await HourlyTimeline(q);

        var recent = await q
            .OrderByDescending(r => r.AccessTime)
            .Take(30)
            .Select(r => new { r.AccessTime, r.FilePath, r.FileName, r.AccessType })
            .ToListAsync();

        return Ok(new { user, byType, topFiles, timeline, recent });
    }

    // GET /api/stats/recent?page=1&pageSize=50
    [HttpGet("recent")]
    public async Task<IActionResult> Recent([FromQuery] int page = 1, [FromQuery] int pageSize = 50)
    {
        if (pageSize < 1 || pageSize > 500) pageSize = 50;
        if (page < 1) page = 1;

        var total = await _db.AccessRecords.CountAsync();
        var items = await _db.AccessRecords
            .OrderByDescending(r => r.AccessTime)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(r => new
            {
                r.AccessTime, r.FilePath, r.FileName, r.FolderPath,
                r.UserName, r.AccessType, r.ClientIp, r.ClientMachine
            })
            .ToListAsync();

        return Ok(new { total, page, pageSize, items });
    }

    // GET /api/stats/search?q=kw1&q=kw2&days=7&dateFrom=&dateTo=&type=&page=1&pageSize=50
    [HttpGet("search")]
    public async Task<IActionResult> Search([FromQuery] SearchFilter filter, [FromQuery] int page = 1, [FromQuery] int pageSize = 50)
    {
        if (pageSize < 1 || pageSize > 500) pageSize = 50;
        if (page < 1) page = 1;

        var query = ApplyFilter(_db.AccessRecords.AsQueryable(), filter);

        var total = await query.CountAsync();
        var items = await query
            .OrderByDescending(r => r.AccessTime)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(r => new
            {
                r.AccessTime, r.FilePath, r.FileName, r.FolderPath,
                r.UserName, r.AccessType, r.ClientIp, r.ClientMachine
            })
            .ToListAsync();

        return Ok(new { total, page, pageSize, items });
    }

    // GET /api/stats/search/export?(same filters)&tzOffsetMinutes=540
    // CSV (UTF-8 with BOM so Excel detects the encoding). Times are shown in the
    // browser's time zone, with a UTC column for unambiguous processing.
    [HttpGet("search/export")]
    public async Task Export([FromQuery] SearchFilter filter, [FromQuery] int tzOffsetMinutes = 0)
    {
        var query = ApplyFilter(_db.AccessRecords.AsNoTracking(), filter)
            .OrderByDescending(r => r.AccessTime)
            .Take(MaxExportRows);

        var offset = TimeSpan.FromMinutes(Math.Clamp(tzOffsetMinutes, -14 * 60, 14 * 60));
        var offsetLabel = (offset < TimeSpan.Zero ? "-" : "+") + offset.ToString(@"hh\:mm");
        var fileName = $"file-access-{DateTime.UtcNow.Add(offset):yyyyMMdd-HHmm}.csv";

        Response.ContentType = "text/csv; charset=utf-8";
        Response.Headers.ContentDisposition = $"attachment; filename=\"{fileName}\"";

        await using var writer = new StreamWriter(Response.Body, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        await writer.WriteLineAsync(CsvLine(
            $"{Messages.Get("csv.time")} (UTC{offsetLabel})", Messages.Get("csv.timeUtc"), Messages.Get("csv.user"),
            Messages.Get("csv.type"), Messages.Get("csv.fileName"), Messages.Get("csv.folder"), Messages.Get("csv.path"),
            Messages.Get("csv.ip"), Messages.Get("csv.machine")));

        var rows = 0;
        await foreach (var r in query.AsAsyncEnumerable())
        {
            var utc = DateTime.SpecifyKind(r.AccessTime, DateTimeKind.Utc);
            await writer.WriteLineAsync(CsvLine(
                utc.Add(offset).ToString("yyyy-MM-dd HH:mm:ss"), utc.ToString("yyyy-MM-ddTHH:mm:ssZ"), r.UserName,
                r.AccessType, r.FileName, r.FolderPath, r.FilePath, r.ClientIp, r.ClientMachine));
            rows++;
        }
        await writer.FlushAsync();

        await _audit.WriteAsync(HttpContext, "export.csv", $"rows={rows}, filter={filter.Describe()}");
    }

    internal const int MaxExportRows = 200_000;

    private static IQueryable<Models.AccessRecord> ApplyFilter(IQueryable<Models.AccessRecord> query, SearchFilter f)
    {
        if (!string.IsNullOrWhiteSpace(f.DateFrom) && DateTime.TryParse(f.DateFrom, out var dtFrom))
            query = query.Where(r => r.AccessTime >= dtFrom.ToUniversalTime());
        else if (f.Days > 0)
            query = query.Where(r => r.AccessTime >= DateTime.UtcNow.AddDays(-f.Days));

        if (!string.IsNullOrWhiteSpace(f.DateTo) && DateTime.TryParse(f.DateTo, out var dtTo))
            query = query.Where(r => r.AccessTime < dtTo.AddDays(1).ToUniversalTime());

        if (f.Q != null)
            foreach (var kw in f.Q.Where(k => !string.IsNullOrWhiteSpace(k)))
            {
                var k = kw;
                query = query.Where(r =>
                    r.FileName.Contains(k) ||
                    r.FilePath.Contains(k) ||
                    r.FolderPath.Contains(k) ||
                    r.UserName.Contains(k) ||
                    (r.ClientIp != null && r.ClientIp.Contains(k)) ||
                    (r.ClientMachine != null && r.ClientMachine.Contains(k)));
            }

        if (!string.IsNullOrWhiteSpace(f.Type))
            query = query.Where(r => r.AccessType == f.Type);

        if (!string.IsNullOrWhiteSpace(f.Ip))
            query = query.Where(r => r.ClientIp != null && r.ClientIp.Contains(f.Ip));

        return query;
    }

    internal static string CsvLine(params string?[] fields) => string.Join(",", fields.Select(CsvField));

    // Quotes every field, and neutralizes values Excel would run as a formula (CSV injection),
    // e.g. a file named "=HYPERLINK(...).txt".
    internal static string CsvField(string? value)
    {
        value ??= "";
        if (value.Length > 0 && "=+-@\t\r".Contains(value[0]))
            value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }
}

public class SearchFilter
{
    public string[]? Q { get; set; }
    public int Days { get; set; } = 7;
    public string? DateFrom { get; set; }
    public string? DateTo { get; set; }
    public string? Type { get; set; }
    public string? Ip { get; set; }

    public string Describe() =>
        $"q=[{string.Join(" ", Q ?? [])}], days={Days}, from={DateFrom}, to={DateTo}, type={Type}, ip={Ip}";
}
