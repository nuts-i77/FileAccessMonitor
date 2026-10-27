using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FileAccessMonitor.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")]
public class AlertsController : ControllerBase
{
    private readonly AlertService _alerts;
    private readonly AuditLog _audit;

    public AlertsController(AlertService alerts, AuditLog audit)
    {
        _alerts = alerts;
        _audit = audit;
    }

    // GET /api/alerts  — secrets are never returned, only whether they are set
    [HttpGet]
    public IActionResult Get()
    {
        var s = _alerts.Settings;
        return Ok(new
        {
            s.Enabled, s.DeleteThreshold, s.WriteThreshold, s.WindowMinutes, s.CooldownMinutes, s.Language,
            s.WebhookFormat, webhookUrlSet = s.HasWebhook,
            s.SmtpHost, s.SmtpPort, s.SmtpUseSsl, s.SmtpUser, smtpPasswordSet = !string.IsNullOrEmpty(s.SmtpPassword),
            s.MailFrom, s.MailTo,
        });
    }

    // PUT /api/alerts
    [HttpPut]
    public async Task<IActionResult> Put([FromBody] AlertSettingsRequest req)
    {
        if (Validate(req) is { } error) return BadRequest(new { error });

        var updated = FromRequest(req);
        _alerts.Save(updated);

        await _audit.WriteAsync(HttpContext, "alerts.update",
            $"enabled={updated.Enabled}, delete={updated.DeleteThreshold}, write={updated.WriteThreshold}, " +
            $"window={updated.WindowMinutes}m, cooldown={updated.CooldownMinutes}m, webhook={updated.HasWebhook}, email={updated.HasMail}");
        return Ok(new { message = Messages.Get("alerts.saved") });
    }

    // POST /api/alerts/test  — sends a test message with the values in the form (not saved),
    // or with the saved settings when no body is sent
    [HttpPost("test")]
    public async Task<IActionResult> Test([FromBody] AlertSettingsRequest? req = null)
    {
        if (req != null && Validate(req) is { } error) return BadRequest(new { error });

        var s = req == null ? _alerts.Settings : FromRequest(req);
        if (!s.HasWebhook && !s.HasMail)
            return BadRequest(new { error = Messages.Get("alerts.noChannel") });

        var results = await _alerts.SendTestAsync(s);
        await _audit.WriteAsync(HttpContext, "alerts.test",
            string.Join(", ", results.Select(r => $"{r.Channel}={(r.Ok ? "ok" : "failed")}")));

        var failed = results.Where(r => !r.Ok).ToList();
        if (failed.Count > 0)
            return BadRequest(new { error = Messages.Get("alerts.testFailed", string.Join(" / ", failed.Select(f => $"{f.Channel}: {f.Error}"))) });
        return Ok(new { message = Messages.Get("alerts.testSent") });
    }

    private static string? Validate(AlertSettingsRequest req)
    {
        if (req.DeleteThreshold < 0 || req.WriteThreshold < 0 || req.WindowMinutes < 1 || req.CooldownMinutes < 1
            || req.SmtpPort is < 1 or > 65535)
            return Messages.Get("alerts.invalid");
        // Half-filled email settings would silently never send
        if (string.IsNullOrWhiteSpace(req.SmtpHost) != string.IsNullOrWhiteSpace(req.MailTo))
            return Messages.Get(string.IsNullOrWhiteSpace(req.SmtpHost) ? "alerts.smtpHostRequired" : "alerts.mailToRequired");
        return null;
    }

    // Secrets: null keeps the stored value, "" clears it
    private AlertSettings FromRequest(AlertSettingsRequest req)
    {
        var current = _alerts.Settings;
        return new AlertSettings
        {
            Enabled = req.Enabled,
            DeleteThreshold = req.DeleteThreshold,
            WriteThreshold = req.WriteThreshold,
            WindowMinutes = req.WindowMinutes,
            CooldownMinutes = req.CooldownMinutes,
            Language = req.Language == "en" ? "en" : "ja",
            WebhookFormat = req.WebhookFormat is "teams" or "generic" ? req.WebhookFormat : "slack",
            WebhookUrl = req.WebhookUrl == null ? current.WebhookUrl : req.WebhookUrl.Trim(),
            SmtpHost = req.SmtpHost?.Trim(),
            SmtpPort = req.SmtpPort,
            SmtpUseSsl = req.SmtpUseSsl,
            SmtpUser = req.SmtpUser?.Trim(),
            SmtpPassword = req.SmtpPassword ?? current.SmtpPassword,
            MailFrom = req.MailFrom?.Trim(),
            MailTo = req.MailTo?.Trim(),
        };
    }
}

public record AlertSettingsRequest(
    bool Enabled, int DeleteThreshold, int WriteThreshold, int WindowMinutes, int CooldownMinutes,
    string? Language, string? WebhookFormat, string? WebhookUrl,
    string? SmtpHost, int SmtpPort, bool SmtpUseSsl, string? SmtpUser, string? SmtpPassword,
    string? MailFrom, string? MailTo);
