using FileAccessMonitor.Controllers;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Tests;

// The history over a real (in-memory) SQLite database: the query shapes, the index and the Windows case rules
public class FileHistoryDbTests : IDisposable
{
    private static readonly DateTime T0 = new(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc);
    private readonly SqliteConnection _conn = new("Data Source=:memory:");
    private readonly AccessDbContext _db;

    public FileHistoryDbTests()
    {
        _conn.Open();
        _db = new AccessDbContext(new DbContextOptionsBuilder<AccessDbContext>().UseSqlite(_conn).Options);
        _db.Database.EnsureCreated();
        SchemaV110History.ApplyAsync(_db).GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        _db.Dispose();
        _conn.Dispose();
    }

    private void Add(double minutes, string type, string path, string? newPath = null, string server = "FS01", bool folder = false,
        bool denied = false, string user = "u")
    {
        _db.AccessRecords.Add(new AccessRecord
        {
            AccessTime = T0.AddMinutes(minutes), AccessType = type, FilePath = path, NewPath = newPath, ServerName = server, IsFolder = folder,
            Denied = denied, UserName = user, FileName = Path.GetFileName(path), FolderPath = Path.GetDirectoryName(path) ?? "",
        });
        _db.SaveChanges();
    }

    private Task<HistoryOutcome> Run(string path, string server = "FS01", IReadOnlyList<ScopeEntry>? scope = null) =>
        new FileHistory(new EfHistorySource(_db), () => T0.AddDays(2))
            .BuildAsync(new HistoryRequest(server, path, null), scope);

    [Fact]
    public async Task Follows_renames_and_folder_moves_through_the_database()
    {
        Add(1, "Create", @"D:\x\a\f.txt");
        Add(2, "Write", @"D:\x\a\f.txt");
        Add(3, "Rename", @"D:\x\a", @"D:\x\b", folder: true);
        Add(4, "Rename", @"D:\x\b\f.txt", @"D:\x\b\g.txt");
        Add(5, "Read", @"D:\x\b\g.txt");
        Add(6, "Create", @"D:\x\a\f.txt", server: "FS02");   // another server's file of the same name

        foreach (var start in new[] { @"D:\x\a\f.txt", @"D:\x\b\g.txt" })
        {
            var r = (await Run(start)).Result!;
            Assert.Equal(["create", "write", "move", "rename", "read"], r.Steps.Select(s => s.Kind));
            Assert.Equal("created", r.Origin);
            Assert.Equal("exists", r.End);
        }
        Assert.Equal(["create"], (await Run(@"D:\x\a\f.txt", "FS02")).Result!.Steps.Select(s => s.Kind));
    }

    [Fact]
    public async Task Windows_paths_match_whatever_the_letter_case()
    {
        // the Security log and the USN journal can spell the same path differently
        Add(1, "Create", @"D:\Docs\Report.txt");
        Add(2, "Rename", @"D:\Docs\Report.txt", @"D:\docs\archive\REPORT.TXT");
        Add(3, "Read", @"D:\DOCS\ARCHIVE\report.txt");
        var r = (await Run(@"D:\DOCS\ARCHIVE\report.txt")).Result!;
        Assert.Equal(["create", "move", "read"], r.Steps.Select(s => s.Kind));

        // the other way: a folder rename recorded in another case than the file's path
        Add(10, "Create", @"D:\Proj\One\a.txt");
        Add(11, "Rename", @"D:\Proj\One", @"D:\proj\TWO", folder: true);
        Add(12, "Read", @"D:\Proj\Two\a.txt");
        var folder = (await Run(@"D:\Proj\Two\a.txt")).Result!;
        Assert.Equal(["create", "move", "read"], folder.Steps.Select(s => s.Kind));
    }

    [Fact]
    public async Task Linux_paths_are_exact()
    {
        Add(1, "Create", "/srv/share/a");
        Add(2, "Rename", "/srv/share/a", "/srv/share/B");
        Add(3, "Read", "/srv/share/b");
        Assert.Equal(["gap", "read"], (await Run("/srv/share/b")).Result!.Steps.Select(s => s.Kind));
    }

    [Fact]
    public async Task A_viewer_gets_the_scoped_history_and_a_refusal_outside()
    {
        Add(1, "Create", @"D:\pub\f.txt");
        Add(2, "Rename", @"D:\pub\f.txt", @"D:\priv\f.txt");
        var scope = AccessScope.Parse([@"D:\pub"]);
        var r = (await Run(@"D:\pub\f.txt", scope: scope)).Result!;
        Assert.Equal(["create", "move", "gap"], r.Steps.Select(s => s.Kind));
        Assert.Null(r.Steps[1].NewPath);
        Assert.Equal(HistoryStatus.Outside, (await Run(@"D:\priv\f.txt", scope: scope)).Status);
    }

    [Fact]
    public async Task The_rename_lookup_uses_the_partial_index()
    {
        for (var i = 0; i < 50; i++) Add(i, "Read", $@"D:\f{i}.txt");
        Add(60, "Rename", @"D:\f1.txt", @"D:\g.txt");
        // the very query the history runs (EF prints the parameters as ".param set @p value" lines)
        var query = new EfHistorySource(_db).RenamedToQuery("FS01", [@"D:\g.txt", "D:"], new HistoryKey(T0.AddDays(1), 99), null)
            .OrderByDescending(r => r.AccessTime).Take(5).ToQueryString();
        var sqlText = new System.Text.StringBuilder();
        var parameters = new List<(string Name, string Value)>();
        foreach (var line in query.Split('\n').Select(l => l.TrimEnd('\r')))
        {
            if (line.StartsWith(".param set "))
            {
                var rest = line[".param set ".Length..];
                var space = rest.IndexOf(' ');
                var name = rest[..space];
                parameters.Add((name.StartsWith('@') ? name : "@" + name, rest[(space + 1)..]));
            }
            else if (!line.StartsWith("--")) sqlText.AppendLine(line);
        }
        var text = sqlText.ToString();
        foreach (var (name, value) in parameters.OrderByDescending(p => p.Name.Length)) text = text.Replace(name, value);

        await using var cmd = _conn.CreateCommand();
        cmd.CommandText = "EXPLAIN QUERY PLAN " + text;
        var plan = new System.Text.StringBuilder();
        await using (var reader = await cmd.ExecuteReaderAsync())
            while (await reader.ReadAsync()) plan.AppendLine(reader.GetString(3));
        Assert.Contains("IX_AccessRecords_NewPath", plan.ToString());

        // the same index is created once: applying the schema again changes nothing
        await SchemaV110History.ApplyAsync(_db);
    }

    [Fact]
    public void The_csv_neutralizes_formulas_and_follows_the_language()
    {
        var result = new HistoryResult
        {
            Server = "FS01", Path = @"D:\=evil.txt",
            Steps =
            [
                new HistoryStep { Kind = "create", Time = T0, User = "=cmd|' /C calc'!A0", Type = "Create", Path = @"D:\=evil.txt" },
                new HistoryStep { Kind = "gap", Gap = new HistoryGap("outOfScope") },
            ],
        };
        var csv = FileHistoryController.CsvText(result, TimeSpan.FromHours(9));
        var lines = csv.TrimEnd().Split("\r\n");   // CRLF on every OS
        Assert.Equal(3, lines.Length);
        Assert.Contains("\"'=cmd|' /C calc'!A0\"", lines[1]);
        Assert.Contains("2026-11-01 09:00:00", lines[1]);
        Assert.Contains("2026-11-01T00:00:00Z", lines[1]);
    }
}
