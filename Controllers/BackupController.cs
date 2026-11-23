using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FileAccessMonitor.Controllers;

// What the GUI shows about backups (Admin only, read-only). Backups are made, restored and scheduled with
// commands run as an administrator: the web service, which runs without privileges, must not be able to
// write the keys somewhere of its choosing (see BackupSchedule).
[ApiController]
[Route("api/backups")]
[Authorize(Roles = "Admin")]
public class BackupController : ControllerBase
{
    // Without a backup for this long the card warns (a daily backup that stopped, or none at all)
    public static readonly TimeSpan StaleAfter = TimeSpan.FromDays(2);

    // GET /api/backups
    [HttpGet]
    public IActionResult Get() => Ok(Describe(AppPaths.DataDir, DateTime.UtcNow));

    internal static object Describe(string dataDir, DateTime now)
    {
        var schedule = BackupSchedule.Read(dataDir);
        var roots = DataBackup.Roots(dataDir, schedule?.To);
        var list = DataBackup.ListAll(roots);
        var latest = list.Where(b => b.Reason != DataBackup.ReasonBeforeRestore).Select(b => (DateTime?)b.Created).Max();
        long? dbBytes = null;
        try { dbBytes = new FileInfo(Path.Combine(dataDir, DataBackup.DatabaseFile)).Length; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return new
        {
            schedule = schedule is { Enabled: true } ? new { time = schedule.Time, keep = schedule.Keep, folder = schedule.To } : null,
            defaultRoot = DataBackup.DefaultRoot(dataDir),
            databaseBytes = dbBytes,
            latest,
            stale = latest == null || now - latest > StaleAfter,
            commandPrefix = CommandPrefix(),
            backups = list.Select(b => new
            {
                name = b.Name, created = b.Created, reason = b.Reason,
                dataVersion = b.DataVersion ?? b.AppVersion, bytes = b.Bytes, collectorIncluded = b.CollectorIncluded,
                folder = Path.GetDirectoryName(b.Path),
            }),
        };
    }

    // This program on the command line (the GUI adds the verb and its arguments)
    internal static string CommandPrefix()
    {
        var exe = Environment.ProcessPath ?? (OperatingSystem.IsWindows() ? "FileAccessMonitor.exe" : "/opt/fileaccessmonitor/FileAccessMonitor");
        return OperatingSystem.IsWindows() ? $"& \"{exe}\"" : $"sudo {exe}";
    }
}
