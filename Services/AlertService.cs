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

// Stored under "Alerts" in settings.json. WebhookUrl and SmtpPassword are kept encrypted
// (ASP.NET Core Data Protection, keys protected with machine DPAPI).
public class AlertSettings
{
    public bool Enabled { get; set; }
    public int DeleteThreshold { get; set; } = 100;
    public int WriteThreshold { get; set; }
    public int WindowMinutes { get; set; } = 5;
    public int CooldownMinutes { get; set; } = 30;
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

    [JsonIgnore] public AlertRules Rules => new(DeleteThreshold, WriteThreshold, WindowMinutes, CooldownMinutes);
    [JsonIgnore] public bool HasWebhook => !string.IsNullOrWhiteSpace(WebhookUrl);
    [JsonIgnore] public bool HasMail => !string.IsNullOrWhiteSpace(SmtpHost) && !string.IsNullOrWhiteSpace(MailTo);
}

public record ChannelResult(string Channel, bool Ok, string? Error);

public class AlertService
{
    private const string SettingsKey = "Alerts";
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly IDataProtector _protector;
    private readonly IHttpClientFactory _http;
    private readonly AuditLog _audit;
    private readonly ILogger<AlertService> _logger;

    private volatile AlertSettings _settings;
    private AlertDetector _detector;

    public AlertService(IDataProtectionProvider dataProtection, IHttpClientFactory http,
        AuditLog audit, ILogger<AlertService> logger)
    {
        _protector = dataProtection.CreateProtector("FileAccessMonitor.Alerts");
        _http = http;
        _audit = audit;
        _logger = logger;
        _settings = Load();
        _detector = new AlertDetector(_settings.Rules);
    }

    public AlertSettings Settings => _settings;

    // Called by the collector with each saved batch.
    public void Observe(IReadOnlyList<AccessRecord> records)
    {
        var settings = _settings;
        if (!settings.Enabled) return;

        if (_detector.Rules != settings.Rules)
            _detector = new AlertDetector(settings.Rules);

        foreach (var alert in _detector.Process(records))
            _ = Task.Run(() => SendAlertAsync(alert, settings));
    }

    // Settings with decrypted secrets. The controller masks them before returning to the browser.
    public AlertSettings Load()
    {
        var node = SettingsStore.Load()[SettingsKey];
        var s = node?.Deserialize<AlertSettings>(JsonOptions) ?? new AlertSettings();
        s.WebhookUrl = Unprotect(s.WebhookUrl);
        s.SmtpPassword = Unprotect(s.SmtpPassword);
        return s;
    }

    public void Save(AlertSettings settings)
    {
        var stored = JsonSerializer.SerializeToNode(settings, JsonOptions)!.AsObject();
        stored["WebhookUrl"] = Protect(settings.WebhookUrl);
        stored["SmtpPassword"] = Protect(settings.SmtpPassword);
        SettingsStore.Update(root => root[SettingsKey] = stored);
        _settings = settings;
    }

    public async Task<List<ChannelResult>> SendTestAsync(AlertSettings s)
    {
        var title = Messages.GetIn(s.Language, "alert.testTitle");
        var body = Messages.GetIn(s.Language, "alert.testBody", Environment.MachineName);
        return await SendAsync(s, title, body, null);
    }

    private async Task SendAlertAsync(Alert alert, AlertSettings s)
    {
        var (title, body) = Format(alert, s.Language);
        _logger.LogWarning("Alert: {Title} {User} {Count}", title, alert.UserName, alert.Count);
        var results = await SendAsync(s, title, body, alert);
        var channels = string.Join(", ", results.Select(r => $"{r.Channel}={(r.Ok ? "ok" : "failed")}"));
        await _audit.WriteAsync(AuditLog.SystemUser, "alert.sent",
            $"type={alert.AccessType}, user={alert.UserName}, count={alert.Count}, channels=[{channels}]");
    }

    internal static (string Title, string Body) Format(Alert a, string lang)
    {
        var title = Messages.GetIn(lang, a.AccessType == "Delete" ? "alert.deleteTitle" : "alert.writeTitle");
        string Local(DateTime utc) => utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
        var client = a.ClientIp == null ? "-" : a.ClientMachine == null ? a.ClientIp : $"{a.ClientIp} ({a.ClientMachine})";

        var sb = new StringBuilder();
        sb.AppendLine(Messages.GetIn(lang, "alert.user", a.UserName));
        sb.AppendLine(Messages.GetIn(lang, "alert.count", a.Count, a.WindowMinutes));
        sb.AppendLine(Messages.GetIn(lang, "alert.period", Local(a.FromUtc), Local(a.ToUtc)));
        sb.AppendLine(Messages.GetIn(lang, "alert.client", client));
        sb.AppendLine(Messages.GetIn(lang, "alert.server", Environment.MachineName));
        sb.AppendLine(Messages.GetIn(lang, "alert.folders"));
        foreach (var (folder, count) in a.TopFolders) sb.AppendLine($"  {folder} ({count})");
        sb.AppendLine(Messages.GetIn(lang, "alert.samples"));
        foreach (var path in a.SamplePaths) sb.AppendLine($"  {path}");
        return ($"[FileAccessMonitor] {title}", sb.ToString().TrimEnd());
    }

    private async Task<List<ChannelResult>> SendAsync(AlertSettings s, string title, string body, Alert? alert)
    {
        var results = new List<ChannelResult>();
        if (s.HasWebhook) results.Add(await TrySend("webhook", () => SendWebhookAsync(s, title, body, alert)));
        if (s.HasMail) results.Add(await TrySend("email", () => SendMailAsync(s, title, body)));
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

    private async Task SendWebhookAsync(AlertSettings s, string title, string body, Alert? alert)
    {
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
            "generic" => new { title, text = body, alert },
            _ => new { text = $"*{title}*\n{body}" },   // Slack incoming webhook
        };

        using var client = _http.CreateClient();
        client.Timeout = TimeSpan.FromSeconds(15);
        using var response = await client.PostAsJsonAsync(s.WebhookUrl, payload);
        response.EnsureSuccessStatusCode();
    }

    private static async Task SendMailAsync(AlertSettings s, string title, string body)
    {
        using var message = new MailMessage
        {
            From = new MailAddress(string.IsNullOrWhiteSpace(s.MailFrom) ? $"filemonitor@{Environment.MachineName}" : s.MailFrom),
            Subject = title,
            Body = body,
            BodyEncoding = Encoding.UTF8,
            SubjectEncoding = Encoding.UTF8,
        };
        foreach (var to in s.MailTo!.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            message.To.Add(to);

        using var smtp = new SmtpClient(s.SmtpHost, s.SmtpPort) { EnableSsl = s.SmtpUseSsl, Timeout = 15000 };
        if (!string.IsNullOrWhiteSpace(s.SmtpUser))
            smtp.Credentials = new NetworkCredential(s.SmtpUser, s.SmtpPassword);
        await smtp.SendMailAsync(message);
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
