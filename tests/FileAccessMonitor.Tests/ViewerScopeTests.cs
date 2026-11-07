using System.Security.Claims;
using System.Text;
using System.Text.Json;
using FileAccessMonitor.Controllers;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileAccessMonitor.Tests;

// 1.11: a Viewer without folders sees nothing; everything needs the explicit "all folders" choice
public class ViewerScopeTests : IDisposable
{
    private readonly SqliteConnection _conn = new("Data Source=:memory:");
    private readonly ServiceProvider _services;

    public ViewerScopeTests()
    {
        _conn.Open();
        _services = new ServiceCollection()
            .AddLogging()
            .AddDbContext<AccessDbContext>(o => o.UseSqlite(_conn))
            .AddScoped<ServerConfigService>()
            .BuildServiceProvider();
        using var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        db.Database.EnsureCreated();
        db.AccessRecords.Add(Record(@"D:\Share\Sales\a.xlsx"));
        db.AccessRecords.Add(Record(@"D:\Share\HR\b.docx"));
        db.SaveChanges();
    }

    public void Dispose()
    {
        _services.Dispose();
        _conn.Dispose();
    }

    private static AccessRecord Record(string path) => new()
    {
        FilePath = path, FileName = Path.GetFileName(path), FolderPath = Path.GetDirectoryName(path)!,
        UserName = "u", AccessType = "Read", AccessTime = DateTime.UtcNow, ServerName = "FS01",
    };

    private static ClaimsPrincipal Viewer(string id) =>
        new(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, id), new Claim(ClaimTypes.Role, "Viewer")], "test"));

    private static ClaimsPrincipal Admin() =>
        new(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "admin"), new Claim(ClaimTypes.Role, "Admin")], "test"));

    private void SetScope(string id, string paths = "", bool all = false)
    {
        using var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        db.UserScopes.Add(new UserScope { UserId = id, Paths = paths, AllFolders = all });
        db.SaveChanges();
    }

    private (StatsController Controller, IServiceScope Scope) Stats(ClaimsPrincipal user, MemoryStream? body = null)
    {
        var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var http = new DefaultHttpContext { User = user };
        if (body != null) http.Response.Body = body;
        var controller = new StatsController(new UserScopeService(db),
            new AuditLog(_services.GetRequiredService<IServiceScopeFactory>(), NullLogger<AuditLog>.Instance))
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
        return (controller, scope);
    }

    private static JsonElement Json(IActionResult result) =>
        JsonSerializer.SerializeToElement(Assert.IsType<OkObjectResult>(result).Value, new JsonSerializerOptions(JsonSerializerDefaults.Web));

    [Fact]
    public void The_scope_of_a_viewer_is_nothing_unless_folders_or_all_folders_are_set()
    {
        SetScope("some", @"D:\Share\Sales");
        SetScope("all", all: true);
        using var scope = _services.CreateScope();
        var scopes = new UserScopeService(scope.ServiceProvider.GetRequiredService<AccessDbContext>());

        Assert.Null(scopes.Get(Admin()));                           // Admins: everything
        Assert.Empty(scopes.Get(Viewer("nobody"))!);                // no row: nothing
        Assert.Single(scopes.Get(Viewer("some"))!);                 // folders
        Assert.Null(scopes.Get(Viewer("all")));                     // all folders: everything

        Assert.Equal(0, scopes.Records(Viewer("nobody")).Count());
        Assert.Equal(1, scopes.Records(Viewer("some")).Count());
        Assert.Equal(2, scopes.Records(Viewer("all")).Count());
        Assert.Equal(2, scopes.Records(Admin()).Count());
    }

    [Fact]
    public async Task A_row_without_folders_and_without_all_folders_sees_nothing_on_the_stats_api()
    {
        SetScope("empty"); // what is left when the last folder is removed
        var (c, scope) = Stats(Viewer("empty"));
        using (scope)
        {
            Assert.Equal(0, Json(await c.Search(new SearchFilter(), 1, 50)).GetProperty("total").GetInt32());
            Assert.Equal(0, Json(await c.Recent(1, 50)).GetProperty("total").GetInt32());
            Assert.Equal(0, Json(await c.Summary(30)).GetProperty("total").GetInt32());
            Assert.Empty(Json(await c.Servers()).EnumerateArray());
        }
    }

    [Fact]
    public async Task All_folders_sees_everything_on_the_stats_api()
    {
        SetScope("all", all: true);
        var (c, scope) = Stats(Viewer("all"));
        using (scope)
        {
            Assert.Equal(2, Json(await c.Search(new SearchFilter(), 1, 50)).GetProperty("total").GetInt32());
            Assert.Equal(2, Json(await c.Recent(1, 50)).GetProperty("total").GetInt32());
            Assert.Single(Json(await c.Servers()).EnumerateArray());
        }
    }

    [Fact]
    public async Task The_csv_export_is_empty_without_folders_and_complete_with_all_folders()
    {
        SetScope("all", all: true);
        async Task<string> Export(string user)
        {
            var body = new MemoryStream();
            var (c, scope) = Stats(Viewer(user), body);
            using (scope) await c.Export(new SearchFilter(), 0);
            return Encoding.UTF8.GetString(body.ToArray());
        }

        var nothing = await Export("nobody");
        var everything = await Export("all");
        Assert.DoesNotContain("a.xlsx", nothing);
        Assert.DoesNotContain("b.docx", nothing);
        Assert.Contains("a.xlsx", everything);
        Assert.Contains("b.docx", everything);
    }

    [Fact]
    public async Task The_permissions_report_is_closed_to_a_viewer_without_folders()
    {
        using var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var http = new DefaultHttpContext { User = Viewer("nobody") };
        var reports = new PermissionReportService(Path.Combine(Path.GetTempPath(), "fam-viewerscope-" + Guid.NewGuid().ToString("N")),
            _services.GetRequiredService<IServiceScopeFactory>(), new AgentJobs(), NullLogger<PermissionReportService>.Instance);
        var c = new PermissionsController(reports, db, new UserScopeService(db), scope.ServiceProvider.GetRequiredService<ServerConfigService>(),
            new AuditLog(_services.GetRequiredService<IServiceScopeFactory>(), NullLogger<AuditLog>.Instance))
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
        Assert.Equal(403, ((ObjectResult)await c.Get(null, @"D:\Share", false, false, null)).StatusCode);
        Assert.Equal(403, ((ObjectResult)await c.Roots(null)).StatusCode);
    }

    // ---- migration

    private async Task AddUserAsync(AccessDbContext db, string id, string? role, string? paths = null, bool all = false)
    {
        db.Users.Add(new ApplicationUser { Id = id, UserName = id, NormalizedUserName = id.ToUpperInvariant() });
        if (role != null)
        {
            var roleId = db.Roles.FirstOrDefault(r => r.Name == role)?.Id;
            if (roleId == null)
            {
                roleId = role + "-id";
                db.Roles.Add(new IdentityRole { Id = roleId, Name = role, NormalizedName = role.ToUpperInvariant() });
            }
            db.UserRoles.Add(new IdentityUserRole<string> { UserId = id, RoleId = roleId });
        }
        if (paths != null) db.UserScopes.Add(new UserScope { UserId = id, Paths = paths, AllFolders = all });
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task The_upgrade_makes_viewers_without_folders_all_folders_once()
    {
        using var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        await AddUserAsync(db, "admin", "Admin");
        await AddUserAsync(db, "norow", "Viewer");                          // no scope row
        await AddUserAsync(db, "blank", "Viewer", paths: "");               // a row without folders
        await AddUserAsync(db, "folders", "Viewer", paths: @"D:\Share\Sales");

        await SchemaV111.ApplyAsync(db);

        bool? All(string id) => db.UserScopes.AsNoTracking().FirstOrDefault(s => s.UserId == id)?.AllFolders;
        Assert.Null(All("admin"));          // Admins need no scope
        Assert.True(All("norow"));
        Assert.True(All("blank"));
        Assert.False(All("folders"));       // folders stay as they are
        Assert.Equal(@"D:\Share\Sales", db.UserScopes.AsNoTracking().First(s => s.UserId == "folders").Paths);

        // An administrator later removes the folders of a viewer: the next start must not turn that into "all folders"
        var folders = db.UserScopes.First(s => s.UserId == "folders");
        folders.Paths = "";
        db.UserScopes.Remove(db.UserScopes.First(s => s.UserId == "norow"));
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        await SchemaV111.ApplyAsync(db);

        Assert.False(All("folders"));
        Assert.Null(All("norow"));
        Assert.Empty(new UserScopeService(db).Get(Viewer("folders"))!);
        Assert.Empty(new UserScopeService(db).Get(Viewer("norow"))!);
    }

    [Fact]
    public async Task The_all_folders_column_is_added_to_an_older_scope_table()
    {
        await using var conn = new SqliteConnection("Data Source=:memory:");
        await conn.OpenAsync();
        using var db = new AccessDbContext(new DbContextOptionsBuilder<AccessDbContext>().UseSqlite(conn).Options);
        db.Database.EnsureCreated();
        await db.Database.ExecuteSqlRawAsync(@"DROP TABLE ""UserScopes""");
        await db.Database.ExecuteSqlRawAsync(@"CREATE TABLE ""UserScopes"" (""UserId"" TEXT NOT NULL CONSTRAINT ""PK_UserScopes"" PRIMARY KEY,
            ""Paths"" TEXT NOT NULL, ""NotifyEmail"" TEXT NULL, ""SendReport"" INTEGER NOT NULL DEFAULT 1)");
        await db.Database.ExecuteSqlRawAsync(@"INSERT INTO ""UserScopes"" VALUES ('v', '', NULL, 1)");
        await AddUserAsync(db, "v", "Viewer");

        await SchemaV111.ApplyAsync(db);
        await SchemaV111.ApplyAsync(db);   // safe to run again

        Assert.True(db.UserScopes.AsNoTracking().Single().AllFolders);
    }
}
