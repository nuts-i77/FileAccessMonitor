using FileAccessMonitor.Models;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class RecordingRulesTests
{
    private static readonly DateTime T0 = new(2026, 11, 1, 1, 0, 0, DateTimeKind.Utc);
    private static readonly HashSet<string> AllTypes = ["Read", "Write", "Delete"];

    private static AccessRecord Rec(string type, double minutes = 0, string path = @"D:\Share\a.mp4", string user = @"CORP\sato") => new()
    {
        UserName = user, AccessType = type, AccessTime = T0.AddMinutes(minutes),
        FilePath = path, FileName = Path.GetFileName(path), FolderPath = Path.GetDirectoryName(path)!,
    };

    [Theory]
    [InlineData("Thumbs.db", true)]
    [InlineData("THUMBS.DB", true)]
    [InlineData("~$report.docx", true)]
    [InlineData("~WRL0001.tmp", true)]
    [InlineData("report.docx", false)]
    [InlineData("a.tmp.mp4", false)]
    public void Default_file_patterns(string fileName, bool excluded)
    {
        var rules = new RecordingRules(new RecordingSettings());
        Assert.Equal(excluded, rules.IsExcludedFile(fileName));
    }

    [Fact]
    public void User_patterns_match_full_or_short_name()
    {
        var rules = new RecordingRules(new RecordingSettings { ExcludeUsers = ["backup", @"CORP\svc-*"] });
        Assert.True(rules.IsExcludedUser(@"CORP\backup"));
        Assert.True(rules.IsExcludedUser("backup"));
        Assert.True(rules.IsExcludedUser(@"CORP\svc-scan"));
        Assert.False(rules.IsExcludedUser(@"OTHER\svc-scan"));
        Assert.False(rules.IsExcludedUser(@"CORP\sato"));
    }

    [Fact]
    public void Process_patterns_ignore_empty_process_name()
    {
        var rules = new RecordingRules(new RecordingSettings { ExcludeProcesses = ["*"] });
        Assert.True(rules.IsExcludedProcess("backup.exe"));
        Assert.False(rules.IsExcludedProcess("")); // SMB accesses carry no process name
    }

    [Fact]
    public void Pattern_characters_other_than_wildcards_are_literal()
    {
        var rules = new RecordingRules(new RecordingSettings { ExcludeFilePatterns = ["a+b (1).txt"] });
        Assert.True(rules.IsExcludedFile("a+b (1).txt"));
        Assert.False(rules.IsExcludedFile("aab (1).txt"));
    }

    [Fact]
    public void Repeated_reads_within_sliding_window_are_merged()
    {
        var m = new ReadMerger();
        var window = TimeSpan.FromMinutes(5);
        Assert.True(m.ShouldRecord(Rec("Read", 0), window));
        Assert.False(m.ShouldRecord(Rec("Read", 4), window));
        Assert.False(m.ShouldRecord(Rec("Read", 8), window)); // window restarted at 4
        Assert.True(m.ShouldRecord(Rec("Read", 14), window));
        // other users and files are counted separately
        Assert.True(m.ShouldRecord(Rec("Read", 14, user: @"CORP\suzuki"), window));
        Assert.True(m.ShouldRecord(Rec("Read", 14, path: @"D:\Share\b.mp4"), window));
    }

    [Fact]
    public void Writes_and_disabled_merging_are_always_recorded()
    {
        var m = new ReadMerger();
        var window = TimeSpan.FromMinutes(5);
        Assert.True(m.ShouldRecord(Rec("Write", 0), window));
        Assert.True(m.ShouldRecord(Rec("Write", 1), window));
        Assert.True(m.ShouldRecord(Rec("Read", 0), TimeSpan.Zero));
        Assert.True(m.ShouldRecord(Rec("Read", 1), TimeSpan.Zero));
    }

    [Fact]
    public void Delete_access_followed_by_4660_is_a_deletion()
    {
        var t = new DeleteTracker(_ => false);
        t.Add("0x4", "0x10", Rec("Delete"), null, AllTypes, T0);
        var r = t.Confirm("0x4", "0x10");
        Assert.Equal("Delete", r?.AccessType);
        Assert.False(t.HasPending);
        Assert.Null(t.Confirm("0x4", "0x10"));
    }

    [Fact]
    public void Delete_access_without_4660_is_a_rename_when_the_path_is_gone()
    {
        var t = new DeleteTracker(_ => false);
        t.Add("0x4", "0x10", Rec("Delete"), null, AllTypes, T0);
        Assert.Empty(t.Expire(T0.AddSeconds(1), T0.AddSeconds(1)));
        var r = Assert.Single(t.Expire(T0.AddSeconds(3), T0.AddSeconds(1)));
        Assert.Equal("Rename", r.AccessType);
    }

    [Fact]
    public void Delete_access_without_4660_is_a_write_when_the_path_was_replaced()
    {
        // Office saves by renaming the old file away and a new file into its place
        var t = new DeleteTracker(_ => true);
        t.Add("0x4", "0x10", Rec("Delete"), null, AllTypes, T0);
        var r = Assert.Single(t.Expire(T0, T0.AddSeconds(3)));
        Assert.Equal("Write", r.AccessType);
    }

    [Fact]
    public void Resolved_types_follow_the_folder_settings()
    {
        var gone = new DeleteTracker(_ => false);
        gone.Add("0x4", "0x10", Rec("Delete"), null, new HashSet<string> { "Read" }, T0);
        Assert.Empty(gone.Expire(T0, T0, force: true)); // renames follow the Delete setting

        var replaced = new DeleteTracker(_ => true);
        replaced.Add("0x4", "0x10", Rec("Delete"), "Read", new HashSet<string> { "Read" }, T0);
        Assert.Equal("Read", Assert.Single(replaced.Expire(T0, T0, force: true)).AccessType);

        var deleted = new DeleteTracker(_ => false);
        deleted.Add("0x4", "0x10", Rec("Delete"), null, new HashSet<string> { "Read" }, T0);
        Assert.Null(deleted.Confirm("0x4", "0x10"));
    }

    [Fact]
    public void Reused_handle_resolves_the_earlier_access()
    {
        var t = new DeleteTracker(_ => false);
        t.Add("0x4", "0x10", Rec("Delete", path: @"D:\Share\a.txt"), null, AllTypes, T0);
        t.Add("0x4", "0x10", Rec("Delete", path: @"D:\Share\b.txt"), null, AllTypes, T0);
        Assert.Equal("Delete", t.Confirm("0x4", "0x10")?.AccessType);
        var renamed = Assert.Single(t.Expire(T0, T0));
        Assert.Equal((@"D:\Share\a.txt", "Rename"), (renamed.FilePath, renamed.AccessType));
    }

    [Fact]
    public void Delete_right_is_split_from_the_rest_of_the_mask()
    {
        var mask = EventLogCollectorService.ParseMask("0x10002");
        Assert.Equal("Delete", EventLogCollectorService.ParseAccessType(mask));
        Assert.Equal("Write", EventLogCollectorService.ParseAccessType(mask & ~EventLogCollectorService.DeleteRight));
        Assert.Null(EventLogCollectorService.ParseAccessType(0x10000L & ~EventLogCollectorService.DeleteRight));
    }
}
