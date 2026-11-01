using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Tests;

public class AccessScopeTests : IDisposable
{
    private readonly SqliteConnection _conn = new("Data Source=:memory:");
    private readonly AccessDbContext _db;

    public AccessScopeTests()
    {
        _conn.Open();
        _db = new AccessDbContext(new DbContextOptionsBuilder<AccessDbContext>().UseSqlite(_conn).Options);
        _db.Database.EnsureCreated();
        foreach (var path in new[]
        {
            @"D:\Share\Sales\a.xlsx", @"D:\Share\Sales\sub\b.docx", @"D:\Share\Sales",
            @"D:\Share\Sales2\c.txt", @"D:\Share\HR\d.pdf", @"D:\Share\50%_off\e.txt", @"D:\Share\50x_off\f.txt",
        })
            _db.AccessRecords.Add(new AccessRecord
            {
                FilePath = path, FileName = Path.GetFileName(path), FolderPath = Path.GetDirectoryName(path)!,
                UserName = "u", AccessType = "Read", AccessTime = DateTime.UtcNow,
            });
        _db.SaveChanges();
    }

    public void Dispose()
    {
        _db.Dispose();
        _conn.Dispose();
    }

    private List<string> Visible(params string[] scope) =>
        AccessScope.Apply(_db.AccessRecords, scope).Select(r => r.FilePath).OrderBy(p => p).ToList();

    [Fact]
    public void Shows_the_folder_and_everything_inside_it_only()
    {
        Assert.Equal([@"D:\Share\Sales", @"D:\Share\Sales\a.xlsx", @"D:\Share\Sales\sub\b.docx"], Visible(@"D:\Share\Sales"));
    }

    [Fact]
    public void Matches_case_insensitively_and_combines_folders()
    {
        Assert.Equal([@"D:\Share\HR\d.pdf", @"D:\Share\Sales2\c.txt"], Visible(@"d:\share\hr", @"D:\SHARE\Sales2\"));
    }

    [Fact]
    public void Like_wildcards_in_paths_are_literal()
    {
        Assert.Equal([@"D:\Share\50%_off\e.txt"], Visible(@"D:\Share\50%_off"));
    }

    [Fact]
    public void Drive_root_scope_covers_the_drive()
    {
        Assert.Equal(7, Visible(@"D:\").Count);
        Assert.Equal(@"D:\", AccessScope.Normalize(@"D:"));
        Assert.Equal(@"D:\Share", AccessScope.Normalize(@" D:\Share\ "));
    }

    [Fact]
    public void Parses_one_path_per_line()
    {
        Assert.Equal([@"D:\A", @"D:\B"], AccessScope.ParsePaths("D:\\A\r\n\n D:\\B\\ \nd:\\a"));
        Assert.True(AccessScope.Contains([@"D:\A"], @"D:\A\x.txt"));
        Assert.False(AccessScope.Contains([@"D:\A"], @"D:\AB\x.txt"));
    }
}
