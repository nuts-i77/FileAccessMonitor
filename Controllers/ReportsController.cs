using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace FileAccessMonitor.Controllers;

// The scheduled report e-mail: settings, a test send, and a preview
[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")]
public class ReportsController(ScheduledReportService scheduler, AlertService alerts, AuditLog audit,
    UserManager<ApplicationUser> users) : ControllerBase
{
    // GET /api/reports/settings
    [HttpGet("settings")]
    public async Task<IActionResult> GetSettings()
    {
        var s = ReportSettings.Load();
        var (lastSlot, lastSent, next) = await scheduler.InfoAsync(s);
        return Ok(new
        {
            s.Enabled, s.Frequency, s.DayOfWeek, s.DayOfMonth, s.Time, s.Csv, s.ScopedViewers, s.Webhook, s.TopN,
            lastSlot = lastSlot?.ToString("yyyy-MM-dd HH:mm"),   // the server's local time
            lastSentAt = lastSent,
            nextSlot = s.Enabled ? next.ToString("yyyy-MM-dd HH:mm") : null,
            smtpReady = alerts.Settings.HasMail,
            webhookReady = alerts.Settings.HasWebhook,
        });
    }

    // PUT /api/reports/settings
    [HttpPut("settings")]
    public async Task<IActionResult> PutSettings([FromBody] ReportSettingsRequest req)
    {
        var updated = new ReportSettings
        {
            Enabled = req.Enabled, Frequency = req.Frequency ?? "", DayOfWeek = req.DayOfWeek, DayOfMonth = req.DayOfMonth,
            Time = req.Time ?? "", Csv = req.Csv, ScopedViewers = req.ScopedViewers, Webhook = req.Webhook, TopN = req.TopN,
        };
        if (updated.Validate() is { } invalid) return BadRequest(new { error = Messages.Get(invalid) });
        // Without a mail server the report could never be sent
        if (updated.Enabled && !alerts.Settings.HasMail) return BadRequest(new { error = Messages.Get("report.smtpRequired") });

        var old = ReportSettings.Load();
        updated.Save();
        // Turned on or rescheduled: nothing is sent now, the first report is the next slot
        if (updated.Enabled && (!old.Enabled || !old.SameSchedule(updated)))
            await scheduler.ResetSlotAsync(updated);

        await audit.WriteAsync(HttpContext, "report.settings",
            $"enabled={updated.Enabled}, frequency={updated.Frequency}, dayOfWeek={updated.DayOfWeek}, dayOfMonth={updated.DayOfMonth}, time={updated.Time}, " +
            $"csv={updated.Csv}, scopedViewers={updated.ScopedViewers}, webhook={updated.Webhook}, topN={updated.TopN}");
        return Ok(new { message = Messages.Get("report.saved") });
    }

    // POST /api/reports/test  — the last full period to the main recipients. With {"scopedViewer": "name"}: that
    // viewer's report, mailed to the signed-in administrator only (to check what the viewer gets).
    [HttpPost("test")]
    public async Task<IActionResult> Test([FromBody] ReportTestRequest? req = null, CancellationToken ct = default)
    {
        if (!alerts.Settings.HasMail) return BadRequest(new { error = Messages.Get("report.smtpRequired") });
        var viewer = req?.ScopedViewer;
        var email = string.IsNullOrWhiteSpace(viewer) ? null : (await users.FindByNameAsync(User.Identity?.Name ?? ""))?.Email;

        var result = await scheduler.SendTestAsync(viewer, email, ct);
        await audit.WriteAsync(HttpContext, "report.test",
            $"status={result.Status}" + (string.IsNullOrWhiteSpace(viewer) ? "" : $", viewer={viewer}")
            + (result.Errors.Count > 0 ? ", errors=" + string.Join(" / ", result.Errors) : ""));
        return result.Status switch
        {
            "ok" => Ok(new { message = Messages.Get(string.IsNullOrWhiteSpace(viewer) ? "report.testSent" : "report.testSentViewer", string.IsNullOrWhiteSpace(viewer) ? alerts.Settings.MailTo : email) }),
            "busy" => Conflict(new { error = Messages.Get("report.busy") }),
            "noViewer" => NotFound(new { error = Messages.Get("report.noViewer", viewer) }),
            "noRecipient" => BadRequest(new { error = Messages.Get("report.noAdminEmail") }),
            _ => BadRequest(new { error = Messages.Get("report.testFailed", string.Join(" / ", result.Errors)) }),
        };
    }

    // GET /api/reports/preview  — the HTML of the report of the last full period
    [HttpGet("preview")]
    public async Task<IActionResult> Preview(CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store";
        return Content(await scheduler.PreviewAsync(ct), "text/html; charset=utf-8");
    }
}

public record ReportSettingsRequest(bool Enabled, string? Frequency, int DayOfWeek, int DayOfMonth, string? Time,
    bool Csv = true, bool ScopedViewers = true, bool Webhook = false, int TopN = 10);

public record ReportTestRequest(string? ScopedViewer);
