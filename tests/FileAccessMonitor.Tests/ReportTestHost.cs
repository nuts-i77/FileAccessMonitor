using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileAccessMonitor.Tests;

// What the report tests share: an in-memory database, fakes of the other features, and a mailer that sends nothing
internal sealed class ReportTestHost : IDisposable
{
    public static readonly DateTime Monday = new(2026, 11, 2, 9, 0, 0, DateTimeKind.Utc);   // a weekly slot (Monday 09:00)

    private readonly SqliteConnection _conn = new("Data Source=:memory:");
    private readonly ServiceProvider _services;
    public IServiceScopeFactory Scopes { get; }
    public FakePermissions Permissions { get; } = new();
    public FakeIntegrity Integrity { get; } = new();
    public ReportBuilder Builder { get; }
    public AuditLog Audit { get; }

    public ReportTestHost()
    {
        _conn.Open();
        _services = new ServiceCollection()
            .AddDbContext<AccessDbContext>(o => o.UseSqlite(_conn))
            .BuildServiceProvider();
        Scopes = _services.GetRequiredService<IServiceScopeFactory>();
        using (var scope = Scopes.CreateScope())
            scope.ServiceProvider.GetRequiredService<AccessDbContext>().Database.EnsureCreated();
        Builder = new ReportBuilder(Scopes, Permissions, Integrity, NullLogger<ReportBuilder>.Instance);
        Audit = new AuditLog(Scopes, NullLogger<AuditLog>.Instance);
    }

    public void Dispose()
    {
        _services.Dispose();
        _conn.Dispose();
    }

    public void Db(Action<AccessDbContext> change)
    {
        using var scope = Scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        change(db);
        db.SaveChanges();
    }

    public T Query<T>(Func<AccessDbContext, T> read)
    {
        using var scope = Scopes.CreateScope();
        return read(scope.ServiceProvider.GetRequiredService<AccessDbContext>());
    }

    public void Access(string server, string path, string type, string user, DateTime time, bool denied = false, bool folder = false)
    {
        Db(db => db.AccessRecords.Add(new AccessRecord
        {
            ServerName = server, FilePath = path, FileName = Path.GetFileName(path), FolderPath = Path.GetDirectoryName(path) ?? "",
            AccessType = type, UserName = user, AccessTime = time, Denied = denied, IsFolder = folder,
        }));
    }

    public void Viewer(string id, string name, string paths, string? email, bool sendReport = true)
    {
        Db(db =>
        {
            db.Users.Add(new ApplicationUser { Id = id, UserName = name, NormalizedUserName = name.ToUpperInvariant() });
            db.UserScopes.Add(new UserScope { UserId = id, Paths = paths, NotifyEmail = email, SendReport = sendReport });
        });
    }

    public static AlertSettings Smtp(string language = "en", string mailTo = "ops@example.com") =>
        new() { SmtpHost = "smtp.example.invalid", MailTo = mailTo, Language = language };

    // The report of the week ending at `slot` (UTC), for everyone or a scope
    public static ReportRequest Weekly(DateTime? slot = null, IReadOnlyList<ScopeEntry>? scope = null, string language = "en", bool csv = false, int topN = 10)
    {
        var to = slot ?? Monday;
        return new ReportRequest(to.AddDays(-7), to, to.AddDays(-14), to.AddDays(-7), to, "weekly", language, topN, csv, scope);
    }

    public static ReportSettings Settings(bool enabled = true) => new() { Enabled = enabled, ScopedViewers = false };
}

internal sealed class FakeClock(DateTime utc) : TimeProvider
{
    private DateTime _utc = utc;
    public void Set(DateTime utc) => _utc = utc;
    public void Advance(TimeSpan by) => _utc += by;
    public override DateTimeOffset GetUtcNow() => new(DateTime.SpecifyKind(_utc, DateTimeKind.Utc));
}

internal sealed class FakeMailer : IReportMailer
{
    public List<(string To, ReportMail Mail)> Sent { get; } = [];
    public List<(string Title, string Text)> Webhooks { get; } = [];
    public Func<string, Exception?>? FailFor { get; set; }
    public TaskCompletionSource? Gate { get; set; }
    public int Attempts { get; private set; }

    public async Task SendMailAsync(AlertSettings smtp, string to, ReportMail mail)
    {
        Attempts++;
        if (Gate != null) await Gate.Task;
        if (FailFor?.Invoke(to) is { } ex) throw ex;
        Sent.Add((to, mail));
    }

    public Task<ChannelResult> SendWebhookAsync(AlertSettings settings, string title, string text)
    {
        Webhooks.Add((title, text));
        return Task.FromResult(new ChannelResult("webhook", true, null));
    }
}

internal sealed class FakePermissions : IPermissionReports
{
    public List<StoredPermissionReport> Reports { get; } = [];
    public Task<StoredPermissionReport?> GetLastAsync(string server, string root, CancellationToken ct = default) =>
        Task.FromResult(Reports.FirstOrDefault(r => r.Server == server && r.Root == root));
    public Task<List<StoredPermissionReport>> ListAsync(CancellationToken ct = default) => Task.FromResult(Reports.ToList());
    public Task<StoredPermissionReport> ScanAsync(string server, string root, PermissionScanOptions options, CancellationToken ct) =>
        throw new InvalidOperationException("a report must never start a scan");
}

internal sealed class FakeIntegrity : IIntegrityStatus
{
    public IntegritySummary Summary { get; set; } = new("disabled", null, null, 0, null, 0, "", 0, null);
    public Task<IntegritySummary> GetSummaryAsync(CancellationToken ct = default) => Task.FromResult(Summary);
}
