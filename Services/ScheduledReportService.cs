using System.Globalization;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Services;

// How a report leaves the server (a seam, so tests need no SMTP server)
public interface IReportMailer
{
    Task SendMailAsync(AlertSettings smtp, string to, ReportMail mail);
    Task<ChannelResult> SendWebhookAsync(AlertSettings settings, string title, string text);
}

public sealed class AlertReportMailer(AlertService alerts) : IReportMailer
{
    public Task SendMailAsync(AlertSettings smtp, string to, ReportMail mail) =>
        AlertService.SendHtmlMailAsync(smtp, to, mail.Subject, mail.Text, mail.Html, mail.Attachments);

    public Task<ChannelResult> SendWebhookAsync(AlertSettings settings, string title, string text) =>
        alerts.SendWebhookTextAsync(settings, title, text);
}

// What is kept in the database between ticks (CollectorStates), so a restart neither loses nor repeats a report
public record ReportState(DateTime? LastSlot, DateTime? AttemptSlot, int Attempts, DateTime? LastAttemptUtc);

public enum ReportAction { None, Init, Send, SkipMissed, SkipFailed }

public record ReportDecision(ReportAction Action, DateTime Slot);

public record ReportSendResult(bool MainOk, int Recipients, int Scoped, int Failed, List<string> Errors);

public record ReportTestResult(string Status, List<string> Errors);   // ok | failed | busy | noViewer | noRecipient

// Sends the report on schedule. One tick a minute decides from the settings, the clock and the stored
// state (ReportSchedule/Decide are pure and unit-tested with a fake clock):
//  - the latest slot is not handled yet and is within the catch-up window: send it
//  - it is older than the window (the service was down): skip it, never send stale reports
//  - a failed send is retried every 15 minutes, 3 times; then the slot is skipped
public class ScheduledReportService : BackgroundService
{
    public const int MaxAttempts = 4;   // the first try and 3 retries
    public static readonly TimeSpan RetryAfter = TimeSpan.FromMinutes(15);
    public const int MaxScopedMails = 50;
    private const string KeyLastSlot = "Report.LastSlot", KeyAttempts = "Report.Attempts", KeyLastSent = "Report.LastSent";
    private const string SlotFormat = "yyyy-MM-ddTHH:mm:ss";

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ReportBuilder _builder;
    private readonly AuditLog _audit;
    private readonly ILogger<ScheduledReportService> _logger;
    private readonly IReportMailer _mailer;
    private readonly TimeProvider _clock;
    private readonly TimeZoneInfo _zone;
    private readonly Func<ReportSettings> _settings;
    private readonly Func<AlertSettings> _alertSettings;
    // One send at a time: a scheduled run, a test, and a retry never overlap
    private readonly SemaphoreSlim _gate = new(1, 1);

    public ScheduledReportService(IServiceScopeFactory scopeFactory, ReportBuilder builder, AuditLog audit,
        ILogger<ScheduledReportService> logger, AlertService? alerts = null, IReportMailer? mailer = null,
        TimeProvider? clock = null, TimeZoneInfo? zone = null, Func<ReportSettings>? settings = null, Func<AlertSettings>? alertSettings = null)
    {
        _scopeFactory = scopeFactory;
        _builder = builder;
        _audit = audit;
        _logger = logger;
        _mailer = mailer ?? new AlertReportMailer(alerts ?? throw new ArgumentNullException(nameof(alerts)));
        _clock = clock ?? TimeProvider.System;
        _zone = zone ?? TimeZoneInfo.Local;
        _settings = settings ?? ReportSettings.Load;
        _alertSettings = alertSettings ?? (() => alerts!.Settings);
    }

    private DateTime NowUtc => _clock.GetUtcNow().UtcDateTime;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        do
        {
            try { await TickAsync(stoppingToken); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "The scheduled report check failed.");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    // What to do now. Pure.
    public static ReportDecision Decide(ReportSettings s, DateTime nowUtc, TimeZoneInfo zone, ReportState state)
    {
        var slot = ReportSchedule.LatestSlotAtOrBefore(s, nowUtc, zone);
        if (!s.Enabled) return new ReportDecision(ReportAction.None, slot);
        if (state.LastSlot == null) return new ReportDecision(ReportAction.Init, slot);   // enabled by hand-editing settings.json
        if (state.LastSlot >= slot) return new ReportDecision(ReportAction.None, slot);

        if (state.AttemptSlot == slot && state.Attempts > 0)
        {
            if (state.Attempts >= MaxAttempts) return new ReportDecision(ReportAction.SkipFailed, slot);
            if (state.LastAttemptUtc is { } last && nowUtc < last + RetryAfter) return new ReportDecision(ReportAction.None, slot);
            return new ReportDecision(ReportAction.Send, slot);
        }
        return nowUtc - ReportSchedule.ToUtc(slot, zone) > ReportSchedule.CatchUpWindow(s.Frequency)
            ? new ReportDecision(ReportAction.SkipMissed, slot)
            : new ReportDecision(ReportAction.Send, slot);
    }

    // One check of the clock (called every minute; public for tests)
    public async Task TickAsync(CancellationToken ct)
    {
        var s = _settings();
        if (!s.Enabled || s.Validate() != null) return;
        await _gate.WaitAsync(ct);
        try
        {
            var now = NowUtc;
            var state = await LoadStateAsync();
            var decision = Decide(s, now, _zone, state);
            var slotText = decision.Slot.ToString(SlotFormat, CultureInfo.InvariantCulture);
            switch (decision.Action)
            {
                case ReportAction.Init:
                    await SaveStateAsync(decision.Slot, null);
                    break;
                case ReportAction.SkipMissed:
                    await SaveStateAsync(decision.Slot, null);
                    await _audit.WriteAsync(AuditLog.SystemUser, "report.skipped", $"reason=missed, slot={slotText}");
                    break;
                case ReportAction.SkipFailed:
                    await SaveStateAsync(decision.Slot, null);
                    await _audit.WriteAsync(AuditLog.SystemUser, "report.skipped", $"reason=failed, slot={slotText}, error={state.Attempts} attempts failed");
                    break;
                case ReportAction.Send:
                    await SendSlotAsync(s, decision.Slot, state, ct);
                    break;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task SendSlotAsync(ReportSettings s, DateTime slot, ReportState state, CancellationToken ct)
    {
        var slotText = slot.ToString(SlotFormat, CultureInfo.InvariantCulture);
        ReportSendResult result;
        try
        {
            result = await SendAllAsync(s, _alertSettings(), slot, test: false, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            result = new ReportSendResult(false, 0, 0, 1, [ex.Message]);
        }

        if (result.MainOk)
        {
            // saved right after the mail left: a crash between the two can send one report twice
            await SaveStateAsync(slot, null, sent: NowUtc);
            await _audit.WriteAsync(AuditLog.SystemUser, "report.sent",
                $"recipients={result.Recipients}, scoped={result.Scoped}, failed={result.Failed}, slot={slotText}"
                + (result.Errors.Count > 0 ? ", errors=" + string.Join(" / ", result.Errors) : ""));
            return;
        }

        var attempts = (state.AttemptSlot == slot ? state.Attempts : 0) + 1;
        _logger.LogWarning("The scheduled report of {Slot} could not be sent (attempt {Attempts}): {Error}", slotText, attempts, string.Join(" / ", result.Errors));
        if (attempts >= MaxAttempts)
        {
            // Mail is the failing channel: no notification about it, only the operation log
            await SaveStateAsync(slot, null);
            await _audit.WriteAsync(AuditLog.SystemUser, "report.skipped", $"reason=failed, slot={slotText}, error={string.Join(" / ", result.Errors)}");
            return;
        }
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        await SetAsync(db, KeyAttempts, $"{slotText};{attempts};{NowUtc:O}");
        await db.SaveChangesAsync(ct);
    }

    // ---- sending

    private ReportRequest RequestFor(ReportSettings s, AlertSettings a, DateTime slot, IReadOnlyList<ScopeEntry>? scope)
    {
        var (from, to) = ReportSchedule.Period(s, slot);
        return new ReportRequest(ReportSchedule.ToUtc(from, _zone), ReportSchedule.ToUtc(to, _zone),
            ReportSchedule.ToUtc(ReportSchedule.PreviousFrom(s, from), _zone), from, to, s.Frequency,
            a.Language, s.TopN, s.Csv, scope);
    }

    // The main report to the notification recipients (all servers), the webhook summary, and a scoped
    // report to each viewer with a notification address. The main mail comes first: when it fails
    // nothing else is sent, so a retry does not send the others twice.
    private async Task<ReportSendResult> SendAllAsync(ReportSettings s, AlertSettings a, DateTime slot, bool test, CancellationToken ct)
    {
        var errors = new List<string>();
        if (!a.HasMail) return new ReportSendResult(false, 0, 0, 1, [Messages.GetIn(a.Language, "report.smtpRequired")]);

        var now = NowUtc;
        var main = await _builder.BuildMailAsync(RequestFor(s, a, slot, null), a, now, test, ct);
        try
        {
            await _mailer.SendMailAsync(a, a.MailTo!, main);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new ReportSendResult(false, 0, 0, 1, [ex.Message]);
        }
        var recipients = a.MailTo!.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Length;
        var failed = 0;

        if (s.Webhook && a.HasWebhook && main.WebhookText != null)
        {
            var hook = await _mailer.SendWebhookAsync(a, main.WebhookTitle ?? main.Subject, main.WebhookText);
            if (!hook.Ok)
            {
                failed++;
                errors.Add("webhook: " + hook.Error);
            }
        }

        var scoped = 0;
        if (s.ScopedViewers && !test)
        {
            var viewers = await ScopedRecipientsAsync(a, ct);
            if (viewers.Count > MaxScopedMails)
            {
                errors.Add($"{viewers.Count - MaxScopedMails} scoped reports not sent (limit {MaxScopedMails} per run)");
                viewers = viewers.Take(MaxScopedMails).ToList();
            }
            foreach (var (user, email, scope) in viewers)
            {
                try
                {
                    var mail = await _builder.BuildMailAsync(RequestFor(s, a, slot, scope), a, now, test: false, ct);
                    await _mailer.SendMailAsync(a, email, mail);
                    scoped++;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    failed++;
                    errors.Add($"{user}: {ex.Message}");
                }
            }
        }
        return new ReportSendResult(true, recipients, scoped, failed, errors);
    }

    // Viewers with a folder scope and a notification address who want the report, except the addresses of the main report
    internal async Task<List<(string User, string Email, List<ScopeEntry> Scope)>> ScopedRecipientsAsync(AlertSettings a, CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var main = a.MailTo!.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var names = await db.Users.AsNoTracking().ToDictionaryAsync(u => u.Id, u => u.UserName ?? u.Id, ct);
        var rows = await db.UserScopes.AsNoTracking().Where(u => u.SendReport && u.NotifyEmail != null && u.NotifyEmail != "").ToListAsync(ct);
        return rows
            .Select(r => (User: names.GetValueOrDefault(r.UserId, r.UserId), Email: r.NotifyEmail!.Trim(), Scope: AccessScope.Parse(r.Paths)))
            .Where(r => r.Scope.Count > 0 && r.Email.Length > 0 && !main.Contains(r.Email))
            .OrderBy(r => r.User, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    // "Send a test report now": the last full period to the main recipients (and the webhook), "[TEST]" in the
    // subject, no scoped viewers, the schedule state untouched. With viewerName: that viewer's scoped report,
    // to adminEmail only, to check what the viewer gets.
    public async Task<ReportTestResult> SendTestAsync(string? viewerName, string? adminEmail, CancellationToken ct)
    {
        if (!await _gate.WaitAsync(0, ct)) return new ReportTestResult("busy", []);
        try
        {
            var s = _settings();
            var a = _alertSettings();
            var slot = ReportSchedule.LatestSlotAtOrBefore(s, NowUtc, _zone);
            if (!string.IsNullOrWhiteSpace(viewerName))
            {
                if (string.IsNullOrWhiteSpace(adminEmail)) return new ReportTestResult("noRecipient", []);
                var viewer = (await ScopedRecipientsAnyAsync(ct))
                    .FirstOrDefault(v => v.User.Equals(viewerName.Trim(), StringComparison.OrdinalIgnoreCase));
                if (viewer == default) return new ReportTestResult("noViewer", []);
                var mail = await _builder.BuildMailAsync(RequestFor(s, a, slot, viewer.Scope), a, NowUtc, test: true, ct);
                try
                {
                    await _mailer.SendMailAsync(a, adminEmail, mail);
                    return new ReportTestResult("ok", []);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    return new ReportTestResult("failed", [ex.Message]);
                }
            }
            var result = await SendAllAsync(s, a, slot, test: true, ct);
            return result.MainOk && result.Failed == 0
                ? new ReportTestResult("ok", [])
                : new ReportTestResult("failed", result.Errors);
        }
        finally
        {
            _gate.Release();
        }
    }

    // Every viewer with a scope (for the preview of a viewer's mail, even without a notification address)
    private async Task<List<(string User, List<ScopeEntry> Scope)>> ScopedRecipientsAnyAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var names = await db.Users.AsNoTracking().ToDictionaryAsync(u => u.Id, u => u.UserName ?? u.Id, ct);
        var rows = await db.UserScopes.AsNoTracking().ToListAsync(ct);
        return rows.Select(r => (User: names.GetValueOrDefault(r.UserId, r.UserId), Scope: AccessScope.Parse(r.Paths)))
            .Where(r => r.Scope.Count > 0).ToList();
    }

    // The HTML of the report of the last full period, for the preview in the GUI
    public async Task<string> PreviewAsync(CancellationToken ct)
    {
        var s = _settings();
        var a = _alertSettings();
        var slot = ReportSchedule.LatestSlotAtOrBefore(s, NowUtc, _zone);
        return (await _builder.BuildMailAsync(RequestFor(s, a, slot, null), a, NowUtc, test: false, ct)).Html;
    }

    // ---- state

    // After the schedule was changed or the report was turned on: the next slot is in the future, nothing is sent now
    public async Task ResetSlotAsync(ReportSettings s)
    {
        await SaveStateAsync(ReportSchedule.LatestSlotAtOrBefore(s, NowUtc, _zone), null);
    }

    public async Task<(DateTime? LastSlot, DateTime? LastSent, DateTime NextSlot)> InfoAsync(ReportSettings s)
    {
        var state = await LoadStateAsync();
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var sent = (await db.CollectorStates.AsNoTracking().FirstOrDefaultAsync(c => c.Key == KeyLastSent))?.Value;
        DateTime? lastSent = DateTime.TryParse(sent, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t) ? t : null;
        return (state.LastSlot, lastSent, ReportSchedule.NextSlot(s, NowUtc, _zone));
    }

    private async Task<ReportState> LoadStateAsync()
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var rows = await db.CollectorStates.AsNoTracking().Where(c => c.Key == KeyLastSlot || c.Key == KeyAttempts).ToListAsync();
        DateTime? Parse(string? v) => DateTime.TryParseExact(v, SlotFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d : null;
        var lastSlot = Parse(rows.FirstOrDefault(r => r.Key == KeyLastSlot)?.Value);

        DateTime? attemptSlot = null, lastAttempt = null;
        var attempts = 0;
        var parts = rows.FirstOrDefault(r => r.Key == KeyAttempts)?.Value.Split(';');
        if (parts is { Length: 3 } && int.TryParse(parts[1], out attempts))
        {
            attemptSlot = Parse(parts[0]);
            lastAttempt = DateTime.TryParse(parts[2], CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var la) ? la : null;
        }
        return new ReportState(lastSlot, attemptSlot, attempts, lastAttempt);
    }

    private async Task SaveStateAsync(DateTime lastSlot, string? attempts, DateTime? sent = null)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        await SetAsync(db, KeyLastSlot, lastSlot.ToString(SlotFormat, CultureInfo.InvariantCulture));
        await SetAsync(db, KeyAttempts, attempts ?? "");
        if (sent != null) await SetAsync(db, KeyLastSent, sent.Value.ToString("O", CultureInfo.InvariantCulture));
        await db.SaveChangesAsync();
    }

    private static async Task SetAsync(AccessDbContext db, string key, string value)
    {
        var row = await db.CollectorStates.FindAsync(key);
        if (row == null) db.CollectorStates.Add(new CollectorState { Key = key, Value = value });
        else row.Value = value;
    }
}
