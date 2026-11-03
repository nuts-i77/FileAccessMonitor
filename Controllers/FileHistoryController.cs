using System.Globalization;
using FileAccessMonitor.Data;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Mvc;

namespace FileAccessMonitor.Controllers;

// The history of one file or folder: its records, followed through renames and moves.
// Lives under api/stats next to the other statistics (see FileHistory for the algorithm).
[ApiController]
[Route("api/stats")]
[Microsoft.AspNetCore.Authorization.Authorize]
public class FileHistoryController(AccessDbContext db, UserScopeService scopes, AuditLog audit) : ControllerBase
{
    // GET /api/stats/file-history?server=&path=&at=&days=0&collapse=true&maxEvents=500
    [HttpGet("file-history")]
    public async Task<IActionResult> Get([FromQuery] string? server, [FromQuery] string? path, [FromQuery] string? at,
        [FromQuery] int days = 0, [FromQuery] bool collapse = true, [FromQuery] int maxEvents = FileHistory.DefaultEvents)
    {
        if (string.IsNullOrWhiteSpace(path)) return BadRequest(new { error = Messages.Get("hist.pathRequired") });
        var outcome = await BuildAsync(server, path, at, days, collapse, maxEvents);
        return outcome.Status switch
        {
            HistoryStatus.Outside => StatusCode(403, new { error = Messages.Get("scope.outside") }),
            HistoryStatus.None => NotFound(new { error = Messages.Get("hist.none") }),
            _ => Ok(outcome.Result),
        };
    }

    // GET /api/stats/file-history/export?(same parameters)&tzOffsetMinutes=540
    // CSV (UTF-8 with BOM), times in the browser's time zone plus UTC, like the search export
    [HttpGet("file-history/export")]
    public async Task<IActionResult> Export([FromQuery] string? server, [FromQuery] string? path, [FromQuery] string? at,
        [FromQuery] int days = 0, [FromQuery] bool collapse = true, [FromQuery] int tzOffsetMinutes = 0)
    {
        if (string.IsNullOrWhiteSpace(path)) return BadRequest(new { error = Messages.Get("hist.pathRequired") });
        var outcome = await BuildAsync(server, path, at, days, collapse, FileHistory.MaxEvents);
        if (outcome.Status == HistoryStatus.Outside) return StatusCode(403, new { error = Messages.Get("scope.outside") });
        if (outcome.Status == HistoryStatus.None) return NotFound(new { error = Messages.Get("hist.none") });
        var result = outcome.Result!;

        var offset = TimeSpan.FromMinutes(Math.Clamp(tzOffsetMinutes, -14 * 60, 14 * 60));
        var fileName = $"file-history-{DateTime.UtcNow.Add(offset):yyyyMMdd-HHmm}.csv";
        Response.ContentType = "text/csv; charset=utf-8";
        Response.Headers.ContentDisposition = $"attachment; filename=\"{fileName}\"";

        await using var writer = new StreamWriter(Response.Body, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        await writer.WriteLineAsync(CsvText(result, offset));
        await writer.FlushAsync();

        await audit.WriteAsync(HttpContext, "export.csv", $"history rows={result.Steps.Count}, server={result.Server}, path={result.Path}");
        return new EmptyResult();
    }

    // The CSV of a history: one line per step (the language follows the request)
    internal static string CsvText(HistoryResult result, TimeSpan offset)
    {
        var offsetLabel = (offset < TimeSpan.Zero ? "-" : "+") + offset.ToString(@"hh\:mm");
        var sb = new System.Text.StringBuilder();
        sb.AppendLine(StatsController.CsvLine(
            $"{Messages.Get("csv.time")} (UTC{offsetLabel})", Messages.Get("csv.timeUtc"), Messages.Get("hist.csv.step"), Messages.Get("csv.user"),
            Messages.Get("csv.type"), Messages.Get("csv.path"), Messages.Get("csv.newPath"), Messages.Get("hist.csv.via"), Messages.Get("csv.detail"),
            Messages.Get("hist.csv.count"), Messages.Get("csv.ip"), Messages.Get("csv.machine"), Messages.Get("csv.server"), Messages.Get("csv.result")));
        foreach (var s in result.Steps)
        {
            var utc = s.Time;
            var count = s.Count > 1 ? $"{s.Count} ({Local(s.FirstTime, offset)} - {Local(s.LastTime, offset)})" : "";
            sb.AppendLine(StatsController.CsvLine(
                Local(utc, offset), utc?.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                Messages.Get(s.Kind == "gap" ? "hist.gap." + s.Gap?.Reason : "hist.kind." + s.Kind),
                s.User, s.Type, s.Path, s.NewPath, s.ViaFolder, s.Detail, count, s.ClientIp, s.ClientMachine, result.Server,
                s.Kind == "gap" ? "" : Messages.Get(s.Denied ? "csv.resultDenied" : "csv.resultOk")));
        }
        return sb.ToString();
    }

    private static string? Local(DateTime? utc, TimeSpan offset) => utc?.Add(offset).ToString("yyyy-MM-dd HH:mm:ss");

    private async Task<HistoryOutcome> BuildAsync(string? server, string path, string? at, int days, bool collapse, int maxEvents)
    {
        DateTime? when = DateTime.TryParse(at, CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var parsed) ? parsed : null;
        var history = new FileHistory(new EfHistorySource(db), () => DateTime.UtcNow);
        return await history.BuildAsync(new HistoryRequest(
            string.IsNullOrWhiteSpace(server) ? ServerConfigService.LocalName : server.Trim(), path, when, Math.Max(0, days), collapse, maxEvents),
            scopes.Get(User));
    }
}
