using FileAccessMonitor.Models;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class UsnCorrelatorTests
{
    private static readonly DateTime T = new(2026, 11, 3, 10, 0, 0, DateTimeKind.Utc);

    private static AccessRecord Rec(string type, string path, double seconds, bool folder = false, bool denied = false) => new()
    {
        AccessType = type, FilePath = path, FileName = Path.GetFileName(path), UserName = "u", AccessTime = T.AddSeconds(seconds),
        IsFolder = folder, Denied = denied,
    };

    private static List<AccessRecord> HoldAndRelease(UsnCorrelator c, AccessRecord r, double caughtUpSeconds = 100)
    {
        c.Hold(r, T);
        c.CaughtUpUtc = T.AddSeconds(caughtUpSeconds);
        return c.Release(T.AddSeconds(1));
    }

    [Fact]
    public void Write_after_a_create_becomes_Create()
    {
        var c = new UsnCorrelator();
        c.AddCreate(@"C:\d\a.txt", T);
        var r = Assert.Single(HoldAndRelease(c, Rec("Write", @"C:\d\a.txt", 1)));
        Assert.Equal("Create", r.AccessType);
    }

    [Theory]
    [InlineData(-30, true)]    // create 30 s before the write: still the first write
    [InlineData(-31, false)]
    [InlineData(2, true)]      // create stamped 2 s after: clock granularity
    [InlineData(3, false)]
    public void Create_must_be_close_to_the_write(double createOffsetSeconds, bool expected)
    {
        var c = new UsnCorrelator();
        c.AddCreate(@"C:\d\a.txt", T.AddSeconds(100 + createOffsetSeconds));
        var r = Assert.Single(HoldAndRelease(c, Rec("Write", @"C:\d\a.txt", 100), 200));
        Assert.Equal(expected ? "Create" : "Write", r.AccessType);
    }

    [Fact]
    public void A_create_is_used_once_and_paths_compare_ignoring_case()
    {
        var c = new UsnCorrelator();
        c.AddCreate(@"C:\D\A.TXT", T);
        c.Hold(Rec("Write", @"c:\d\a.txt", 1), T);
        c.Hold(Rec("Write", @"C:\d\a.txt", 2), T);
        c.CaughtUpUtc = T.AddSeconds(100);
        Assert.Equal(["Create", "Write"], c.Release(T.AddSeconds(1)).Select(r => r.AccessType));
    }

    [Fact]
    public void Write_without_a_create_stays_Write()
    {
        var c = new UsnCorrelator();
        c.AddCreate(@"C:\d\other.txt", T);
        Assert.Equal("Write", Assert.Single(HoldAndRelease(c, Rec("Write", @"C:\d\a.txt", 1))).AccessType);
    }

    [Fact]
    public void Rename_gets_its_new_path()
    {
        var c = new UsnCorrelator();
        c.AddRename(@"C:\d\a.txt", @"C:\d\sub\b.txt", T.AddSeconds(2));
        var r = Assert.Single(HoldAndRelease(c, Rec("Rename", @"C:\d\A.txt", 0)));
        Assert.Equal("Rename", r.AccessType);
        Assert.Equal(@"C:\d\sub\b.txt", r.NewPath);
    }

    [Theory]
    [InlineData(-1, true)]
    [InlineData(-2, false)]
    [InlineData(10, true)]
    [InlineData(11, false)]
    public void Rename_must_follow_the_access_closely(double renameOffsetSeconds, bool expected)
    {
        var c = new UsnCorrelator();
        c.AddRename(@"C:\d\a.txt", @"C:\d\b.txt", T.AddSeconds(100 + renameOffsetSeconds));
        var r = Assert.Single(HoldAndRelease(c, Rec("Rename", @"C:\d\a.txt", 100), 200));
        Assert.Equal(expected ? @"C:\d\b.txt" : null, r.NewPath);
    }

    [Fact]
    public void Several_renames_of_one_path_go_to_the_nearest_each_once()
    {
        var c = new UsnCorrelator();
        c.AddRename(@"C:\d\a.txt", @"C:\d\x.txt", T.AddSeconds(1));
        c.AddRename(@"C:\d\a.txt", @"C:\d\y.txt", T.AddSeconds(9));
        c.Hold(Rec("Rename", @"C:\d\a.txt", 8), T);
        c.Hold(Rec("Rename", @"C:\d\a.txt", 0), T);
        c.CaughtUpUtc = T.AddSeconds(100);
        var released = c.Release(T.AddSeconds(1));
        Assert.Equal([@"C:\d\y.txt", @"C:\d\x.txt"], released.Select(r => r.NewPath));
    }

    [Fact]
    public void Rename_without_a_journal_fact_has_no_new_path()
    {
        var c = new UsnCorrelator();
        Assert.Null(Assert.Single(HoldAndRelease(c, Rec("Rename", @"C:\d\a.txt", 0))).NewPath);
    }

    [Fact]
    public void Record_waits_until_the_journal_has_caught_up()
    {
        var c = new UsnCorrelator();
        c.Hold(Rec("Write", @"C:\d\a.txt", 10), T.AddSeconds(10));
        c.CaughtUpUtc = T.AddSeconds(12.9);
        Assert.Empty(c.Release(T.AddSeconds(11)));
        Assert.True(c.HasHeld);
        c.CaughtUpUtc = T.AddSeconds(13);
        Assert.Single(c.Release(T.AddSeconds(11)));
        Assert.False(c.HasHeld);
    }

    [Fact]
    public void Record_is_released_after_10_seconds_at_the_latest()
    {
        var c = new UsnCorrelator();
        c.Hold(Rec("Write", @"C:\d\a.txt", 10), T.AddSeconds(10));
        Assert.Empty(c.Release(T.AddSeconds(19.9)));
        Assert.Single(c.Release(T.AddSeconds(20)));
    }

    [Fact]
    public void Force_releases_everything()
    {
        var c = new UsnCorrelator();
        c.Hold(Rec("Write", @"C:\d\a.txt", 10), T);
        c.Hold(Rec("Rename", @"C:\d\b.txt", 10), T);
        Assert.Equal(2, c.Release(T, force: true).Count);
    }

    [Fact]
    public void Release_keeps_the_order_of_arrival()
    {
        var c = new UsnCorrelator();
        c.Hold(Rec("Write", @"C:\d\late.txt", 50), T);   // not ready yet
        c.Hold(Rec("Write", @"C:\d\early.txt", 1), T);   // ready, but behind the first
        c.CaughtUpUtc = T.AddSeconds(10);
        Assert.Empty(c.Release(T.AddSeconds(1)));
        c.CaughtUpUtc = T.AddSeconds(60);
        Assert.Equal(["late.txt", "early.txt"], c.Release(T.AddSeconds(1)).Select(r => r.FileName));
    }

    [Fact]
    public void Only_files_written_and_renames_need_correlation()
    {
        Assert.True(UsnCorrelator.NeedsCorrelation(Rec("Write", "C:\\a", 0)));
        Assert.True(UsnCorrelator.NeedsCorrelation(Rec("Rename", "C:\\a", 0)));
        Assert.True(UsnCorrelator.NeedsCorrelation(Rec("Rename", "C:\\a", 0, folder: true)));
        Assert.False(UsnCorrelator.NeedsCorrelation(Rec("Write", "C:\\a", 0, folder: true)));
        Assert.False(UsnCorrelator.NeedsCorrelation(Rec("Write", "C:\\a", 0, denied: true)));
        Assert.False(UsnCorrelator.NeedsCorrelation(Rec("Read", "C:\\a", 0)));
        Assert.False(UsnCorrelator.NeedsCorrelation(Rec("Delete", "C:\\a", 0)));
        Assert.False(UsnCorrelator.NeedsCorrelation(Rec("Permission", "C:\\a", 0)));
    }

    [Fact]
    public void Old_facts_are_pruned_behind_the_journal_position()
    {
        var c = new UsnCorrelator();
        for (var i = 0; i < 1500; i++) c.AddCreate($@"C:\d\{i}.txt", T);
        c.CaughtUpUtc = T.AddMinutes(11);
        c.Release(T.AddMinutes(11)); // prunes
        Assert.Equal(0, c.FactCount);
    }

    [Fact]
    public void Facts_are_capped()
    {
        var c = new UsnCorrelator();
        for (var i = 0; i < UsnCorrelator.MaxFacts + 10; i++) c.AddCreate($@"C:\d\{i}.txt", T.AddMilliseconds(i));
        Assert.True(c.FactCount <= UsnCorrelator.MaxFacts);
    }

    [Fact]
    public void Unavailable_volume_means_the_record_is_not_held()
    {
        // The collector holds a record only where the reader reports a working journal (Covers);
        // a correlator that was never given a record has nothing to release or to wait for.
        var c = new UsnCorrelator();
        Assert.False(c.HasHeld);
        Assert.Empty(c.Release(T));
    }
}
