using FileAccessMonitor.Controllers;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Tests;

// Records from Linux agents carry "/srv/share/a.txt" paths, which are case-sensitive
public class LinuxPathTests : IDisposable
{
    private readonly SqliteConnection _conn = new("Data Source=:memory:");
    private readonly AccessDbContext _db;

    public LinuxPathTests()
    {
        _conn.Open();
        _db = new AccessDbContext(new DbContextOptionsBuilder<AccessDbContext>().UseSqlite(_conn).Options);
        _db.Database.EnsureCreated();
        foreach (var path in new[] { "/srv/share/sales/a.txt", "/srv/share/Sales/b.txt", "/srv/share/sales2/c.txt", "/srv/share/sales" })
            _db.AccessRecords.Add(new AccessRecord
            {
                FilePath = path, FileName = path[(path.LastIndexOf('/') + 1)..], FolderPath = path[..path.LastIndexOf('/')],
                UserName = "u", AccessType = "Read", AccessTime = DateTime.UtcNow, ServerName = "NAS01",
            });
        _db.AccessRecords.Add(new AccessRecord
        {
            FilePath = @"D:\Share\x.txt", FileName = "x.txt", FolderPath = @"D:\Share",
            UserName = "u", AccessType = "Read", AccessTime = DateTime.UtcNow, ServerName = "FS01",
        });
        _db.SaveChanges();
    }

    public void Dispose()
    {
        _db.Dispose();
        _conn.Dispose();
    }

    [Theory]
    [InlineData("/srv/share/a.txt", "/srv/share", true)]
    [InlineData("/srv/share", "/srv/share/", true)]
    [InlineData("/srv/Share/a.txt", "/srv/share", false)]
    [InlineData("/srv/share2/a.txt", "/srv/share", false)]
    [InlineData("/srv/a.txt", "/", true)]
    [InlineData(@"d:\share\a.txt", @"D:\Share", true)]
    [InlineData(@"D:\Share2\a.txt", @"D:\Share", false)]
    public void Folders_match_by_the_rules_of_their_system(string path, string root, bool expected) =>
        Assert.Equal(expected, PathText.IsUnder(path, root));

    [Theory]
    [InlineData("/srv/share/", "/srv/share")]
    [InlineData("/", "/")]
    [InlineData(@"D:\Share\", @"D:\Share")]
    [InlineData("D:", @"D:\")]
    public void Paths_are_normalized(string path, string expected) => Assert.Equal(expected, PathText.Normalize(path));

    [Fact]
    public void Viewing_scopes_match_linux_paths_exactly()
    {
        var visible = AccessScope.Apply(_db.AccessRecords, AccessScope.Parse(["NAS01|/srv/share/sales/"]))
            .Select(r => r.FilePath).OrderBy(p => p).ToList();
        Assert.Equal(["/srv/share/sales", "/srv/share/sales/a.txt"], visible);
    }

    [Fact]
    public void Folder_names_are_the_last_part_of_the_path()
    {
        var names = _db.AccessRecords.GroupBy(r => r.FolderPath).Select(g => new
            {
                g.Key,
                Name = g.Key.Length > 1 && g.Key.StartsWith("/")
                    ? g.Key.Substring(g.Key.LastIndexOf('/') + 1)
                    : g.Key.Length > 0 && EF.Functions.Like(g.Key, @"%\%") ? g.Key.Substring(g.Key.LastIndexOf('\\') + 1) : g.Key,
            })
            .ToDictionary(x => x.Key, x => x.Name);
        Assert.Equal(("sales", "Sales", "share", "Share"),
            (names["/srv/share/sales"], names["/srv/share/Sales"], names["/srv/share"], names[@"D:\Share"]));
    }

    [Fact]
    public void Unused_files_are_summarized_per_linux_subfolder()
    {
        var files = new[]
        {
            new UnusedFilesController.ScannedFile("/srv/share/top.txt", 1, DateTime.UtcNow, false),
            new UnusedFilesController.ScannedFile("/srv/share/sales/a.txt", 10, DateTime.UtcNow, true),
            new UnusedFilesController.ScannedFile("/srv/share/Sales/b.txt", 20, DateTime.UtcNow, false),
        };
        var rows = UnusedFilesController.Summarize("/srv/share", files, new Dictionary<string, DateTime>())
            .ToDictionary(r => r.Path, r => (r.Files, r.UnusedSize));
        Assert.Equal((1, 0L), rows["/srv/share/sales"]);
        Assert.Equal((1, 20L), rows["/srv/share/Sales"]);
        Assert.Equal((1, 1L), rows["/srv/share"]);
    }
}
