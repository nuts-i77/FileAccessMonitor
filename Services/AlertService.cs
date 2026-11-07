using System.Net;
using System.Net.Http.Json;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using FileAccessMonitor.Models;
using Microsoft.AspNetCore.DataProtection;

namespace FileAccessMonitor.Services;

// Stored under "Alerts" in settings.json. WebhookUrl, SmtpPassword and ProxyPassword are kept encrypted
// (ASP.NET Core Data Protection, keys protected with machine DPAPI).
public class AlertSettings
{
    public bool Enabled { get; set; }
    public int DeleteThreshold { get; set; } = 100;
    public int WriteThreshold { get; set; }
    public int ReadThreshold { get; set; }
    // Refused attempts per user within the window (0 = off)
    public int DeniedThreshold { get; set; } = 20;
    // Ransomware-like behaviour: on/off in the GUI, the numbers only in settings.json
    public bool RansomwareEnabled { get; set; } = true;
    public int RansomwareWindowMinutes { get; set; } = 2;
    public int RansomwareSameExtensionRenames { get; set; } = 20;
    public int RansomwareBurstWrites { get; set; } = 100;
    public int RansomwareBurstRenames { get; set; } = 50;
    public int RansomwareNoteFolders { get; set; } = 3;
    public int RansomwareCooldownMinutes { get; set; } = 30;
    public int WindowMinutes { get; set; } = 5;
    public int CooldownMinutes { get; set; } = 30;
    // Notify when an agent has not been in touch for this long (0 = never)
    public int AgentOfflineMinutes { get; set; } = 15;
    public string Language { get; set; } = "ja";
    public string WebhookFormat { get; set; } = "slack";   // slack | teams | generic
    public string? WebhookUrl { get; set; }
    public string? SmtpHost { get; set; }
    public int SmtpPort { get; set; } = 587;
    public bool SmtpUseSsl { get; set; } = true;
    public string? SmtpUser { get; set; }
    public string? SmtpPassword { get; set; }
    public string? MailFrom { get; set; }
    public string? MailTo { get; set; }      // comma or semicolon separated
    // HTTP proxy for webhooks (the service runs as SYSTEM, so the Windows user proxy setting does not apply)
    public string? ProxyUrl { get; set; }
    public string? ProxyUser { get; set; }
    public string? ProxyPassword { get; set; }

    [JsonIgnore] public AlertRules Rules => new(DeleteThreshold, WriteThreshold, WindowMinutes, CooldownMinutes, ReadThreshold,
        DeniedThreshold, new RansomwareRules(RansomwareEnabled, RansomwareWindowMinutes, RansomwareSameExtensionRenames,
            RansomwareBurstWrites, RansomwareBurstRenames, RansomwareNoteFolders, RansomwareCooldownMinutes));
    [JsonIgnore] public bool HasWebhook => !string.IsNullOrWhiteSpace(WebhookUrl);
    [JsonIgnore] public bool HasMail => !string.IsNullOrWhiteSpace(SmtpHost) && !string.IsNullOrWhiteSpace(MailTo);

    // The same SMTP settings, mailing only the given address (for a folder's own recipient)
    public AlertSettings ForRecipient(string mailTo)
    {
        var copy = (AlertSettings)MemberwiseClone();
        copy.WebhookUrl = null;
        copy.MailTo = mailTo;
        return copy;
    }
}

// A Viewer with a folder scope and a notification address: gets the alerts about their folders,
// detected from the records inside the scope only.
public sealed record AlertRecipient(string UserName, IReadOnlyList<ScopeEntry> Paths, string Email, AlertDetector Detector);

public record ChannelResult(string Channel, bool Ok, string? Error);

public record MailAttachmentData(string FileName, byte[] Content, string ContentType);

public class AlertService
{
    private const string SettingsKey = "Alerts";
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly IDataProtector _protector;
    private readonly IHttpClientFactory _http;
    private readonly AuditLog _audit;
    private readonly ILogger<AlertService> _logger;

    private readonly IServiceScopeFactory _scopeFactory;

    private volatile AlertSettings _settings;
    private AlertDetector _detector;
    // Rebuilt when scopes change (ReloadRecipients); null until first needed
    private volatile IReadOnlyList<AlertRecipient>? _recipients;

    public AlertService(IDataProtectionProvider dataProtection, IHttpClientFactory http,
        AuditLog audit, IServiceScopeFactory scopeFactory, ILogger<AlertService> logger)
    {
        _protector = dataProtection.CreateProtector("FileAccessMonitor.Alerts");
        _http = http;
        _audit = audit;
        _scopeFactory = scopeFactory;
        _logger = logger;
        _settings = Load();
        _detector = new AlertDetector(_settings.Rules);
    }

    public AlertSettings Settings => _settings;

    private readonly object _observeLock = new();

    // Called with each saved batch: by the local collector and by agent uploads, on different
    // threads, while the detectors are not thread-safe.
    public void Observe(IReadOnlyList<AccessRecord> records)
    {
        lock (_observeLock) ObserveLocked(records);
    }

    private void ObserveLocked(IReadOnlyList<AccessRecord> records)
    {
        var settings = _settings;
        if (!settings.Enabled) return;

        if (_detector.Rules != settings.Rules)
            _detector = new AlertDetector(settings.Rules);

        foreach (var alert in _detector.Process(records))
            _ = Task.Run(() => SendAlertAsync(alert, settings));

        // Folder recipients: mail only, so SMTP must be set up
        if (string.IsNullOrWhiteSpace(settings.SmtpHost)) return;
        var recipients = _recipients ??= LoadRecipients(settings.Rules);
        foreach (var r in recipients)
        {
            if (r.Detector.Rules != settings.Rules)
            {
                ReloadRecipients();
                return; // rules changed: new detectors start with the next batch
            }
            var inScope = records.Where(rec => AccessScope.Contains(r.Paths, rec.ServerName, rec.FilePath)).ToList();
            if (inScope.Count == 0) continue;
            foreach (var alert in r.Detector.Process(inScope))
                _ = Task.Run(() => SendAlertAsync(alert, settings.ForRecipient(r.Email), r.UserName));
        }
    }

    // Called after a user's scope changes
    public void ReloadRecipients() => _recipients = null;

    private IReadOnlyList<AlertRecipient> LoadRecipients(AlertRules rules)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<Data.AccessDbContext>();
            var names = db.Users.ToDictionary(u => u.Id, u => u.UserName ?? u.Id);
            return db.UserScopes.Where(s => s.NotifyEmail != null).AsEnumerable()
                .Select(s => new AlertRecipient(names.GetValueOrDefault(s.UserId, s.UserId),
                    AccessScope.Parse(s.Paths), s.NotifyEmail!, new AlertDetector(rules)))
                .Where(r => r.Paths.Count > 0)
                .ToList();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not load folder alert recipients.");
            return [];
        }
    }

    // Settings with decrypted secrets. The controller masks them before returning to the browser.
    public AlertSettings Load()
    {
        var node = SettingsStore.Load()[SettingsKey];
        var s = node?.Deserialize<AlertSettings>(JsonOptions) ?? new AlertSettings();
        s.WebhookUrl = Unprotect(s.WebhookUrl);
        s.SmtpPassword = Unprotect(s.SmtpPassword);
        s.ProxyPassword = Unprotect(s.ProxyPassword);
        return s;
    }

    public void Save(AlertSettings settings)
    {
        var stored = JsonSerializer.SerializeToNode(settings, JsonOptions)!.AsObject();
        stored["WebhookUrl"] = Protect(settings.WebhookUrl);
        stored["SmtpPassword"] = Protect(settings.SmtpPassword);
        stored["ProxyPassword"] = Protect(settings.ProxyPassword);
        SettingsStore.Update(root => root[SettingsKey] = stored);
        _settings = settings;
    }

    public async Task<List<ChannelResult>> SendTestAsync(AlertSettings s)
    {
        var title = Messages.GetIn(s.Language, "alert.testTitle");
        var body = Messages.GetIn(s.Language, "alert.testBody", Environment.MachineName);
        return await SendAsync(s, title, body, null);
    }

    // Recording was interrupted (Security log records overwritten before they were collected, or
    // the log cleared). Sent whenever notifications are enabled, regardless of the thresholds.
    public async Task NotifyGapAsync(string serverName, string messageKey, params object[] args)
    {
        var s = _settings;
        if (!s.Enabled || (!s.HasWebhook && !s.HasMail)) return;

        var title = "[FileAccessMonitor] " + Messages.GetIn(s.Language, "gap.title");
        var body = Messages.GetIn(s.Language, messageKey, args) + "\n"
            + Messages.GetIn(s.Language, "alert.server", serverName);
        var results = await SendAsync(s, title, body, null);
        var channels = string.Join(", ", results.Select(r => $"{r.Channel}={(r.Ok ? "ok" : "failed")}"));
        await _audit.WriteAsync(AuditLog.SystemUser, "alert.sent", $"type=gap, server={serverName}, channels=[{channels}]");
    }

    // An agent stopped (or started again) contacting this server. Sent whenever notifications are enabled.
    public async Task NotifyAgentStatusAsync(string agentName, bool offline, DateTime? lastSeenUtc)
    {
        var s = _settings;
        if (!s.Enabled || (!s.HasWebhook && !s.HasMail)) return;

        var lastSeen = lastSeenUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "-";
        var title = "[FileAccessMonitor] " + Messages.GetIn(s.Language, offline ? "agentOffline.title" : "agentOnline.title");
        var body = offline
            ? Messages.GetIn(s.Language, "agentOffline.body", agentName, s.AgentOfflineMinutes, lastSeen)
            : Messages.GetIn(s.Language, "agentOnline.body", agentName);
        var results = await SendAsync(s, title, body, null);
        var channels = string.Join(", ", results.Select(r => $"{r.Channel}={(r.Ok ? "ok" : "failed")}"));
        await _audit.WriteAsync(AuditLog.SystemUser, "alert.sent",
            $"type={(offline ? "agentOffline" : "agentOnline")}, server={agentName}, channels=[{channels}]");
    }

    // An agent's send queue is full and its collection is paused. Sent whenever notifications are enabled.
    public async Task NotifyAgentOutboxFullAsync(string agentName)
    {
        var s = _settings;
        if (!s.Enabled || (!s.HasWebhook && !s.HasMail)) return;

        var title = "[FileAccessMonitor] " + Messages.GetIn(s.Language, "agentOutboxFull.title");
        var body = Messages.GetIn(s.Language, "agentOutboxFull.body", agentName, AgentOutbox.MaxBytes / (1024 * 1024 * 1024) + " GB");
        var results = await SendAsync(s, title, body, null);
        var channels = string.Join(", ", results.Select(r => $"{r.Channel}={(r.Ok ? "ok" : "failed")}"));
        await _audit.WriteAsync(AuditLog.SystemUser, "alert.sent", $"type=agentOutboxFull, server={agentName}, channels=[{channels}]");
    }

    // A notification of a feature (e.g. type "Integrity" when the record chain is broken) to the main
    // channels in the configured language. Sent whenever notifications are enabled.
    public async Task<List<ChannelResult>> NotifyAsync(string type, string titleKey, string bodyKey, bool high, params object[] args)
    {
        var s = _settings;
        if (!s.Enabled || (!s.HasWebhook && !s.HasMail)) return [];

        var prefix = high ? Messages.GetIn(s.Language, "alert.highPriority") + " " : "";
        var title = $"{prefix}[FileAccessMonitor] " + Messages.GetIn(s.Language, titleKey, args);
        var body = Messages.GetIn(s.Language, bodyKey, args);
        var results = new List<ChannelResult>();
        if (s.HasWebhook) results.Add(await TrySend("webhook", () => SendWebhookAsync(s, title, body, null, high)));
        if (s.HasMail) results.Add(await TrySend("email", () => SendMailAsync(s, title, body, high)));
        var channels = string.Join(", ", results.Select(r => $"{r.Channel}={(r.Ok ? "ok" : "failed")}"));
        await _audit.WriteAsync(AuditLog.SystemUser, "alert.sent", $"type={type}, channels=[{channels}]");
        return results;
    }

    // An HTML mail with a plain-text alternative and attachments (scheduled report) to the given
    // addresses, with the SMTP settings of s. Throws when sending fails.
    public static async Task SendHtmlMailAsync(AlertSettings s, string to, string subject, string textBody, string htmlBody,
        IReadOnlyList<MailAttachmentData> attachments)
    {
        using var message = NewMessage(s, to, subject);
        message.Body = textBody;
        message.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(htmlBody, Encoding.UTF8, "text/html"));
        foreach (var a in attachments)
            message.Attachments.Add(new Attachment(new MemoryStream(a.Content), a.FileName, a.ContentType));

        using var smtp = NewSmtpClient(s, attachments.Count > 0 ? 60000 : 15000);
        await smtp.SendMailAsync(message);
    }

    // A text message to the webhook (scheduled report summary); never throws
    public Task<ChannelResult> SendWebhookTextAsync(AlertSettings s, string title, string body) =>
        TrySend("webhook", () => SendWebhookAsync(s, title, body, null));

    // recipient: the folder recipient's user name, or null for the main notification channels
    private async Task SendAlertAsync(Alert alert, AlertSettings s, string? recipient = null)
    {
        var (title, body) = Format(alert, s.Language);
        _logger.LogWarning("Alert: {Title} {User} {Count} {Recipient}", title, alert.UserName, alert.Count, recipient);
        var results = await SendAsync(s, title, body, alert);
        var channels = string.Join(", ", results.Select(r => $"{r.Channel}={(r.Ok ? "ok" : "failed")}"));
        await _audit.WriteAsync(AuditLog.SystemUser, "alert.sent",
            $"type={alert.AccessType}, " + (alert.Rule.Length > 0 ? $"rule={alert.Rule}, " : "")
            + $"server={alert.ServerName}, user={alert.UserName}, count={alert.Count}, channels=[{channels}]"
            + (recipient == null ? "" : $", folderRecipient={recipient}"));
    }

    internal static (string Title, string Body) Format(Alert a, string lang)
    {
        var title = Messages.GetIn(lang, a.AccessType switch
        {
            "Delete" => "alert.deleteTitle",
            "Read" => "alert.readTitle",
            "Denied" => "alert.deniedTitle",
            "Ransomware" => "alert.ransomwareTitle",
            _ => "alert.writeTitle",
        });
        string Local(DateTime utc) => utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
        var client = a.ClientIp == null ? "-" : a.ClientMachine == null ? a.ClientIp : $"{a.ClientIp} ({a.ClientMachine})";

        var sb = new StringBuilder();
        sb.AppendLine(Messages.GetIn(lang, "alert.user", a.UserName));
        sb.AppendLine(Messages.GetIn(lang, "alert.count", a.Count, a.WindowMinutes));
        sb.AppendLine(Messages.GetIn(lang, "alert.period", Local(a.FromUtc), Local(a.ToUtc)));
        if (a.Rule.Length > 0) sb.AppendLine(Messages.GetIn(lang, "alert.rule." + a.Rule));
        if (!string.IsNullOrEmpty(a.Detail)) sb.AppendLine(Messages.GetIn(lang, "alert.detail", a.Detail));
        sb.AppendLine(Messages.GetIn(lang, "alert.client", client));
        sb.AppendLine(Messages.GetIn(lang, "alert.server", a.ServerName.Length > 0 ? a.ServerName : Environment.MachineName));
        sb.AppendLine(Messages.GetIn(lang, "alert.folders"));
        foreach (var (folder, count) in a.TopFolders) sb.AppendLine($"  {folder} ({count})");
        sb.AppendLine(Messages.GetIn(lang, "alert.samples"));
        foreach (var path in a.SamplePaths) sb.AppendLine($"  {path}");
        var prefix = a.Priority == "High" ? Messages.GetIn(lang, "alert.highPriority") + " " : "";
        return ($"{prefix}[FileAccessMonitor] {title}", sb.ToString().TrimEnd());
    }

    private async Task<List<ChannelResult>> SendAsync(AlertSettings s, string title, string body, Alert? alert)
    {
        var results = new List<ChannelResult>();
        if (s.HasWebhook) results.Add(await TrySend("webhook", () => SendWebhookAsync(s, title, body, alert)));
        if (s.HasMail) results.Add(await TrySend("email", () => SendMailAsync(s, title, body, alert?.Priority == "High")));
        return results;
    }

    private async Task<ChannelResult> TrySend(string channel, Func<Task> send)
    {
        try
        {
            await send();
            return new ChannelResult(channel, true, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Sending alert via {Channel} failed.", channel);
            return new ChannelResult(channel, false, ex.Message);
        }
    }

    private async Task SendWebhookAsync(AlertSettings s, string title, string body, Alert? alert, bool high = false)
    {
        var priority = alert?.Priority == "High" || high ? "high" : "normal";
        object payload = s.WebhookFormat switch
        {
            // Teams "Workflows" webhook (Post to a channel when a webhook request is received)
            "teams" => new
            {
                type = "message",
                attachments = new[]
                {
                    new
                    {
                        contentType = "application/vnd.microsoft.card.adaptive",
                        content = new Dictionary<string, object>
                        {
                            ["$schema"] = "http://adaptivecards.io/schemas/adaptive-card.json",
                            ["type"] = "AdaptiveCard",
                            ["version"] = "1.4",
                            ["body"] = new object[]
                            {
                                new { type = "TextBlock", text = title, weight = "Bolder", size = "Medium", wrap = true },
                                new { type = "TextBlock", text = body.Replace("\n", "\n\n"), wrap = true },
                            },
                        },
                    },
                },
            },
            "generic" => new { title, text = body, priority, alert },
            _ => new { text = $"*{title}*\n{body}" },   // Slack incoming webhook
        };

        using var client = string.IsNullOrWhiteSpace(s.ProxyUrl) ? _http.CreateClient() : CreateProxyClient(s);
        client.Timeout = TimeSpan.FromSeconds(15);
        using var response = await client.PostAsJsonAsync(s.WebhookUrl, payload);
        response.EnsureSuccessStatusCode();
    }

    private static HttpClient CreateProxyClient(AlertSettings s)
    {
        var proxy = new WebProxy(s.ProxyUrl!.Trim());
        if (!string.IsNullOrWhiteSpace(s.ProxyUser))
            proxy.Credentials = new NetworkCredential(s.ProxyUser, s.ProxyPassword);
        return new HttpClient(new SocketsHttpHandler { Proxy = proxy, UseProxy = true }, disposeHandler: true);
    }

    private static async Task SendMailAsync(AlertSettings s, string title, string body, bool highPriority = false)
    {
        using var message = NewMessage(s, s.MailTo!, title);
        message.Body = body;
        // High sets the X-Priority: 1, Priority and Importance headers
        if (highPriority) message.Priority = MailPriority.High;

        using var smtp = NewSmtpClient(s, 15000);
        await smtp.SendMailAsync(message);
    }

    // to: comma or semicolon separated
    private static MailMessage NewMessage(AlertSettings s, string to, string subject)
    {
        var message = new MailMessage
        {
            From = new MailAddress(string.IsNullOrWhiteSpace(s.MailFrom) ? $"filemonitor@{Environment.MachineName}" : s.MailFrom),
            Subject = subject,
            BodyEncoding = Encoding.UTF8,
            SubjectEncoding = Encoding.UTF8,
        };
        foreach (var address in to.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            message.To.Add(address);
        return message;
    }

    private static SmtpClient NewSmtpClient(AlertSettings s, int timeoutMs)
    {
        var smtp = new SmtpClient(s.SmtpHost, s.SmtpPort) { EnableSsl = s.SmtpUseSsl, Timeout = timeoutMs };
        if (!string.IsNullOrWhiteSpace(s.SmtpUser))
            smtp.Credentials = new NetworkCredential(s.SmtpUser, s.SmtpPassword);
        return smtp;
    }

    private string? Protect(string? value) =>
        string.IsNullOrEmpty(value) ? null : _protector.Protect(value);

    private string? Unprotect(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        try { return _protector.Unprotect(value); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "A stored alert secret could not be decrypted; please enter it again.");
            return null;
        }
    }
}
