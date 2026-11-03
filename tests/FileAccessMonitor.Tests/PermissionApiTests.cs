using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FileAccessMonitor.Controllers;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileAccessMonitor.Tests;

public class PermissionApiTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "fam-permapi-" + Guid.NewGuid().ToString("N"));
    private readonly SqliteConnection _conn = new("Data Source=:memory:");
    private readonly ServiceProvider _services;
    private readonly AgentJobs _jobs = new();
    private readonly PermissionReportService _reports;
    private static readonly string Server = ServerConfigService.LocalName;
    private static readonly DateTime ScannedAt = new(2026, 11, 3, 1, 0, 0, DateTimeKind.Utc);

    private readonly System.Globalization.CultureInfo _culture = System.Globalization.CultureInfo.CurrentUICulture;

    public PermissionApiTests()
    {
        System.Globalization.CultureInfo.CurrentUICulture = new System.Globalization.CultureInfo("en"); // the texts are checked in English
        _conn.Open();
        _services = new ServiceCollection()
            .AddLogging()
            .AddDbContext<AccessDbContext>(o => o.UseSqlite(_conn))
            .AddScoped<ServerConfigService>()
            .BuildServiceProvider();
        using (var scope = _services.CreateScope()) scope.ServiceProvider.GetRequiredService<AccessDbContext>().Database.EnsureCreated();
        _reports = new PermissionReportService(_dir, _services.GetRequiredService<IServiceScopeFactory>(), _jobs,
            NullLogger<PermissionReportService>.Instance);
    }

    public void Dispose()
    {
        System.Globalization.CultureInfo.CurrentUICulture = _culture;
        _services.Dispose();
        _conn.Dispose();
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    // D:\Share (Everyone may read), Docs (Everyone modify), Docs\Sub (does not inherit), Hr (Authenticated Users read, =cmd group)
    private StoredPermissionReport Sample()
    {
        var b = new PermissionResultBuilder("windows", @"D:\Share", new PermissionScanOptions());
        var admins = b.Principal(@"BUILTIN\Administrators", "S-1-5-32-544");
        var everyone = b.Principal("Everyone", "S-1-1-0");
        var auth = b.Principal(@"NT AUTHORITY\Authenticated Users", "S-1-5-11");
        var evil = b.Principal("=HYPERLINK(\"http://x\")", "S-1-5-21-1-2-3-1500");
        b.AddRow("", 1 | 8, admins, [new PermissionAce(admins, 0, 31, 7)]);
        b.AddRow("Docs", 1 | 8, -1, [new PermissionAce(everyone, 0, 23, 7)]);
        b.AddRow(@"Docs\Sub", 1 | 2 | 8, -1, [new PermissionAce(admins, 0, 31, 7)]);
        b.AddRow("Hr", 1 | 8, -1, [new PermissionAce(auth, 0, 1 | 16, 7), new PermissionAce(evil, 0, 31, 7)]);
        b.AddRow(@"Hr\plan.docx", 8, -1, [new PermissionAce(everyone, 1, 2, 1)]);
        b.AddError(@"D:\Share\Secret: not readable");
        var result = b.Build();
        return new StoredPermissionReport { Server = Server, Root = @"D:\Share", Os = "windows", ScannedAt = ScannedAt, Result = result };
    }

    private PermissionsController Controller(string? role = "Admin", string? scopePaths = null, string userId = "u1")
    {
        var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        if (scopePaths != null && db.UserScopes.Find(userId) == null)
        {
            db.UserScopes.Add(new UserScope { UserId = userId, Paths = scopePaths });
            db.SaveChanges();
        }
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, userId), new(ClaimTypes.Name, "tester") };
        if (role != null) claims.Add(new Claim(ClaimTypes.Role, role));
        var http = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test")) };
        return new PermissionsController(_reports, db, new UserScopeService(db), scope.ServiceProvider.GetRequiredService<ServerConfigService>(),
            new AuditLog(_services.GetRequiredService<IServiceScopeFactory>(), NullLogger<AuditLog>.Instance))
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private static JsonElement Json(IActionResult result)
    {
        var ok = Assert.IsType<OkObjectResult>(result);
        return JsonSerializer.SerializeToElement(ok.Value, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    }

    private static int Status(IActionResult result) => ((ObjectResult)result).StatusCode ?? 200;

    private async Task<IActionResult> GetAsync(PermissionsController c, bool broadOnly = false, bool brokenOnly = false, string? q = null) =>
        await c.Get(null, @"D:\Share", broadOnly, brokenOnly, q);

    [Fact]
    public async Task Store_round_trips_and_keeps_the_latest_per_server_and_folder()
    {
        var report = Sample();
        await _reports.WriteAsync(report, default);
        var back = (await _reports.GetLastAsync("", @"D:\Share\"))!; // the local server by an empty name; a trailing separator
        Assert.Equal((Server, @"D:\Share", ScannedAt, "windows"), (back.Server, back.Root, back.ScannedAt, back.Os));
        Assert.Equal(report.Result.ToJsonString(), back.Result.ToJsonString());
        Assert.NotNull(await _reports.GetLastAsync(Server, @"d:\share")); // Windows paths ignore case

        report.ScannedAt = ScannedAt.AddDays(1);
        await _reports.WriteAsync(report, default);
        var all = await _reports.ListAsync();
        Assert.Equal(ScannedAt.AddDays(1), Assert.Single(all).ScannedAt);
        Assert.Null(await _reports.GetLastAsync(Server, @"D:\Other"));
        Assert.Empty(Directory.GetFiles(_dir, "*.tmp")); // the temporary file is moved over the old one
    }

    [Fact]
    public async Task Linux_roots_are_told_apart_by_case()
    {
        var b = new PermissionResultBuilder("linux", "/srv/Share", new PermissionScanOptions());
        await _reports.WriteAsync(new StoredPermissionReport { Server = "CT115", Root = "/srv/Share", Os = "linux", ScannedAt = ScannedAt, Result = b.Build() }, default);
        Assert.NotNull(await _reports.GetLastAsync("CT115", "/srv/Share"));
        Assert.Null(await _reports.GetLastAsync("CT115", "/srv/share"));
    }

    [Fact]
    public async Task A_corrupt_file_is_ignored()
    {
        await _reports.WriteAsync(Sample(), default);
        File.WriteAllText(Directory.GetFiles(_dir, "*.json").Single(), "{ not json");
        Assert.Null(await _reports.GetLastAsync(Server, @"D:\Share"));
        Assert.Empty(await _reports.ListAsync());
    }

    [Fact]
    public async Task Admin_gets_everything_with_counts_and_levels()
    {
        await _reports.WriteAsync(Sample(), default);
        var view = Json(await GetAsync(Controller()));
        Assert.Equal(5, view.GetProperty("total").GetInt32());
        var counts = view.GetProperty("counts");
        Assert.Equal((1, 1, 1), (counts.GetProperty("high").GetInt32(), counts.GetProperty("medium").GetInt32(), counts.GetProperty("broken").GetInt32()));
        var items = view.GetProperty("items").EnumerateArray().ToList();
        Assert.Equal(["", "Docs", @"Docs\Sub", "Hr", @"Hr\plan.docx"], items.Select(i => i.GetProperty("rel").GetString()!).ToArray());
        var docs = items[1];
        Assert.Equal(@"D:\Share\Docs", docs.GetProperty("path").GetString());
        Assert.Equal("high", docs.GetProperty("severity").GetString());
        Assert.Equal("modify", docs.GetProperty("aces")[0].GetProperty("levelCode").GetString());
        Assert.True(items[2].GetProperty("inheritanceBroken").GetBoolean());
        Assert.True(view.GetProperty("canScan").GetBoolean());
    }

    [Fact]
    public async Task Broad_only_and_broken_only_and_text_filters()
    {
        await _reports.WriteAsync(Sample(), default);
        var c = Controller();
        string[] Rels(JsonElement v) => v.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("rel").GetString()!).ToArray();
        Assert.Equal(["Docs", "Hr"], Rels(Json(await GetAsync(c, broadOnly: true))));
        Assert.Equal([@"Docs\Sub"], Rels(Json(await GetAsync(c, brokenOnly: true))));
        Assert.Equal(["Hr", @"Hr\plan.docx"], Rels(Json(await GetAsync(c, q: "hr"))));
        Assert.Equal(["Docs"], Rels(Json(await GetAsync(c, q: "everyone", broadOnly: true)))); // principal name; the deny entry on plan.docx is not broad access
    }

    [Fact]
    public async Task Paging_splits_the_rows()
    {
        await _reports.WriteAsync(Sample(), default);
        var view = Json(await Controller().Get(null, @"D:\Share", pageSize: 2, page: 3));
        Assert.Equal((5, 1), (view.GetProperty("total").GetInt32(), view.GetProperty("items").GetArrayLength()));
    }

    [Fact]
    public async Task A_scoped_viewer_sees_only_rows_inside_the_scope()
    {
        await _reports.WriteAsync(Sample(), default);
        var c = Controller("Viewer", @"D:\Share\Docs");
        var view = Json(await GetAsync(c));
        Assert.Equal([@"D:\Share\Docs", @"D:\Share\Docs\Sub"], view.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("path").GetString()!).ToArray());
        Assert.False(view.GetProperty("canScan").GetBoolean());
        Assert.True(view.GetProperty("scoped").GetBoolean());
        Assert.Equal(0, view.GetProperty("errors").GetArrayLength()); // the error names a folder outside the scope
        Assert.Equal(1, view.GetProperty("counts").GetProperty("high").GetInt32());
    }

    [Fact]
    public async Task A_scoped_viewer_cannot_open_a_folder_outside_the_scope()
    {
        await _reports.WriteAsync(Sample(), default);
        Assert.Equal(403, Status(await Controller("Viewer", @"D:\Elsewhere").Get(null, @"D:\Share")));
    }

    [Fact]
    public async Task An_unscoped_viewer_gets_nothing()
    {
        await _reports.WriteAsync(Sample(), default);
        var c = Controller("Viewer");
        Assert.Equal(403, Status(await GetAsync(c)));
        Assert.Equal(403, Status(await c.Roots(null)));
        Assert.Equal(403, Status(await c.Export(null, @"D:\Share")));
        Assert.Equal(403, Status(await c.Servers()));
    }

    [Fact]
    public async Task A_missing_scan_is_not_found()
    {
        Assert.Equal(404, Status(await GetAsync(Controller())));
    }

    [Fact]
    public async Task Last_permission_change_comes_from_the_records_and_marks_changes_after_the_scan()
    {
        await _reports.WriteAsync(Sample(), default);
        using (var scope = _services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            AccessRecord Rec(string path, string type, DateTime time, string user = @"CORP\sato", string? server = null) => new()
            {
                FilePath = path, FileName = Path.GetFileName(path), FolderPath = @"D:\Share", UserName = user, AccessType = type,
                AccessTime = time, ServerName = server ?? Server, IsFolder = true,
            };
            db.AccessRecords.AddRange(
                Rec(@"D:\Share\Docs", "Permission", ScannedAt.AddHours(-5), @"CORP\old"),
                Rec(@"d:\share\docs", "Permission", ScannedAt.AddHours(-2), @"CORP\sato"), // the latest, written in another case
                Rec(@"D:\Share\Hr", "Permission", ScannedAt.AddHours(3), @"CORP\tanaka"),     // after the scan
                Rec(@"D:\Share\Docs\Sub", "Write", ScannedAt.AddHours(1)),                       // not a permission change
                Rec(@"D:\Share\Docs\Sub", "Permission", ScannedAt.AddHours(1), server: "OTHERSERVER"));
            db.SaveChanges();
        }
        var items = Json(await GetAsync(Controller())).GetProperty("items").EnumerateArray().ToDictionary(i => i.GetProperty("rel").GetString()!);

        var docs = items["Docs"];
        Assert.Equal(@"CORP\sato", docs.GetProperty("lastChange").GetProperty("user").GetString());
        Assert.False(docs.GetProperty("changedSinceScan").GetBoolean());
        var hr = items["Hr"];
        Assert.Equal(@"CORP\tanaka", hr.GetProperty("lastChange").GetProperty("user").GetString());
        Assert.True(hr.GetProperty("changedSinceScan").GetBoolean());
        Assert.Equal(JsonValueKind.Null, items[@"Docs\Sub"].GetProperty("lastChange").ValueKind);
        Assert.False(items[@"Docs\Sub"].GetProperty("changedSinceScan").GetBoolean());
    }

    private static string[][] Csv(IActionResult result, out byte[] bytes)
    {
        var file = Assert.IsType<FileContentResult>(result);
        Assert.StartsWith("text/csv", file.ContentType);
        bytes = file.FileContents;
        var text = Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);
        return text.Split("\r\n", StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l[1..^1].Split("\",\"").Select(f => f.Replace("\"\"", "\"")).ToArray()).ToArray();
    }

    [Fact]
    public async Task Export_is_csv_with_a_bom_one_line_per_entry_and_safe_against_formulas()
    {
        await _reports.WriteAsync(Sample(), default);
        var lines = Csv(await Controller().Export(null, @"D:\Share"), out var bytes);
        Assert.Equal([0xEF, 0xBB, 0xBF], bytes[..3]);
        Assert.Equal(15, lines[0].Length);
        Assert.Equal(1 + 1 + 1 + 1 + 2 + 1, lines.Length); // header, root, Docs, Docs\Sub, Hr (2 entries), plan.docx
        Assert.All(lines, l => Assert.Equal(15, l.Length));
        var evil = lines.Single(l => l[4].Contains("HYPERLINK"));
        Assert.StartsWith("'=HYPERLINK", evil[4]); // neutralised like the search export
        var docs = lines.Single(l => l[2] == @"D:\Share\Docs");
        Assert.Equal(["Everyone", "S-1-1-0", "Allow", "Modify", "This folder, subfolders and files", "everyone", "High"], docs[4..11]);
        var deny = lines.Single(l => l[2] == @"D:\Share\Hr\plan.docx");
        Assert.Equal(("Deny", "File", "everyone", ""), (deny[6], deny[3], deny[9], deny[10])); // a deny entry for a broad principal is listed, not flagged
        Assert.Equal("Yes", lines.Single(l => l[2] == @"D:\Share\Docs\Sub")[11]);
    }

    [Fact]
    public async Task Export_of_a_scoped_viewer_is_limited_to_the_scope()
    {
        await _reports.WriteAsync(Sample(), default);
        var lines = Csv(await Controller("Viewer", @"D:\Share\Hr").Export(null, @"D:\Share"), out _);
        Assert.DoesNotContain(lines.Skip(1), l => l[2] == @"D:\Share\Docs");
        Assert.Contains(lines, l => l[2] == @"D:\Share\Hr");
    }

    [Fact]
    public async Task Scanning_is_admin_only_by_attribute_and_exports_are_logged()
    {
        var scan = typeof(PermissionsController).GetMethod(nameof(PermissionsController.Scan))!;
        var attr = (Microsoft.AspNetCore.Authorization.AuthorizeAttribute)scan.GetCustomAttributes(typeof(Microsoft.AspNetCore.Authorization.AuthorizeAttribute), false).Single();
        Assert.Equal("Admin", attr.Roles);

        await _reports.WriteAsync(Sample(), default);
        await Controller().Export(null, @"D:\Share");
        using var scope = _services.CreateScope();
        var logged = scope.ServiceProvider.GetRequiredService<AccessDbContext>().AuditLogs.Single(a => a.Action == "permissions.export");
        Assert.Contains("rows=6", logged.Detail);
    }

    [Fact]
    public async Task An_agent_before_1_10_is_refused_and_no_job_is_sent()
    {
        using (var scope = _services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            db.Agents.Add(new Agent { Id = "a1", Name = "FS01", KeyHash = "x", Version = "1.9.0" });
            db.SaveChanges();
        }
        var ex = await Assert.ThrowsAsync<PermissionScanException>(() => _reports.ScanAsync("FS01", @"D:\Share", new PermissionScanOptions(), default));
        Assert.Equal(409, ex.Status);
        Assert.Contains("FS01", ex.Message);
        Assert.Contains("1.9.0", ex.Message);
        Assert.Null(await _jobs.NextAsync("a1", TimeSpan.FromMilliseconds(200), default));
    }

    [Theory]
    [InlineData("1.9.0", true)]
    [InlineData("1.9.12", true)]
    [InlineData("1.10.0", false)]
    [InlineData("1.10.0-beta.1", false)]
    [InlineData("1.10.0+abc123", false)]
    [InlineData("2.0.0", false)]
    [InlineData("0.0.0", true)]
    [InlineData(null, false)]
    [InlineData("garbage", false)]
    public void Agent_versions(string? version, bool tooOld) => Assert.Equal(tooOld, PermissionReportService.IsTooOld(version));

    [Fact]
    public async Task An_agent_that_does_not_know_the_job_gets_the_same_message()
    {
        using (var scope = _services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            db.Agents.Add(new Agent { Id = "a2", Name = "FS02", KeyHash = "x", Version = "1.10.0" }); // a wrong version string
            db.SaveChanges();
        }
        var scan = _reports.ScanAsync("FS02", @"D:\Share", new PermissionScanOptions(), default);
        var job = await _jobs.NextAsync("a2", TimeSpan.FromSeconds(5), default);
        Assert.Equal("permissions", job!.Type);
        Assert.Equal(@"D:\Share", job.Args["path"]!.GetValue<string>());
        Assert.True(_jobs.Complete("a2", job.Id, new JsonObject { ["error"] = "Unknown job permissions; update the agent." }));
        var ex = await Assert.ThrowsAsync<PermissionScanException>(() => scan);
        Assert.Equal(409, ex.Status);
        Assert.Contains("1.10", ex.Message);
    }

    [Fact]
    public async Task An_agents_answer_is_stored_and_a_second_scan_at_the_same_time_is_refused()
    {
        using (var scope = _services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            db.Agents.Add(new Agent { Id = "a3", Name = "FS03", KeyHash = "x", Version = "1.10.0" });
            db.SaveChanges();
        }
        var first = _reports.ScanAsync("FS03", @"D:\Share", new PermissionScanOptions(), default);
        var job = await _jobs.NextAsync("a3", TimeSpan.FromSeconds(5), default);
        var second = await Assert.ThrowsAsync<PermissionScanException>(() => _reports.ScanAsync("fs03", @"d:\share\", new PermissionScanOptions(), default));
        Assert.Equal(409, second.Status);

        var answer = Sample().Result;
        Assert.True(_jobs.Complete("a3", job!.Id, answer));
        var stored = await first;
        Assert.Equal(("FS03", "1.10.0", "windows"), (stored.Server, stored.AgentVersion, stored.Os));
        Assert.Equal(5, (await _reports.GetLastAsync("FS03", @"D:\Share"))!.Result["rows"]!.AsArray().Count);

        // and the folder can be scanned again
        var third = _reports.ScanAsync("FS03", @"D:\Share", new PermissionScanOptions(), default);
        var job2 = await _jobs.NextAsync("a3", TimeSpan.FromSeconds(5), default);
        Assert.True(_jobs.Complete("a3", job2!.Id, new JsonObject { ["exists"] = false }));
        var missing = await Assert.ThrowsAsync<PermissionScanException>(() => third);
        Assert.Equal(400, missing.Status);
    }
}
