using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.Extensions.Logging.Abstractions;

#pragma warning disable CA1416 // the Samba collector is for Linux; these tests use its platform-neutral parts

namespace FileAccessMonitor.Tests;

// 1.11.2: what the audit-trail test found. Saves through temporary names, renames that only change the
// case, repeated writes of one save, and the same on Windows and Linux.
public class TrailFixesTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "fam-trail-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    private static readonly DateTime T = new(2026, 11, 8, 6, 0, 0, DateTimeKind.Utc);

    private static AccessRecord Rec(string type, string path, double seconds, string user = "u") => new()
    {
        AccessType = type, FilePath = path, FileName = Path.GetFileName(path), UserName = user, AccessTime = T.AddSeconds(seconds),
    };

    // ---- Windows: a rename that only changes the case

    [Fact]
    public void A_file_renamed_only_in_case_is_not_there_under_its_old_name()
    {
        Directory.CreateDirectory(_dir);
        var old = Path.Combine(_dir, "case.txt");
        File.WriteAllText(old, "x");
        Assert.True(EventLogCollectorService.ExistsAsNamed(old));
        File.Move(old, Path.Combine(_dir, "CASE.txt"));
        Assert.True(File.Exists(old));                                   // Windows ignores case...
        Assert.False(EventLogCollectorService.ExistsAsNamed(old));       // ...but the name is another one
        Assert.True(EventLogCollectorService.ExistsAsNamed(Path.Combine(_dir, "CASE.txt")));
        Assert.False(EventLogCollectorService.ExistsAsNamed(Path.Combine(_dir, "gone.txt")));
    }

    [Fact]
    public void A_DELETE_access_without_4660_after_a_case_change_is_a_rename()
    {
        var tracker = new DeleteTracker(_ => false);                     // the old name is not there as named
        tracker.Add("1", "h", Rec("Delete", @"C:\d\case.txt", 0), null, new HashSet<string> { "Delete" }, T);
        Assert.Equal("Rename", Assert.Single(tracker.Expire(T, T.AddSeconds(5))).AccessType);
    }

    // ---- Windows: temporary names

    private static readonly HashSet<string> All = new(["Read", "Write", "Delete", "Permission"]);

    [Fact]
    public void A_temporary_file_that_is_deleted_leaves_nothing()
    {
        var tracker = new DeleteTracker(_ => false);
        var r = Rec("Delete", @"C:\d\~WRL0001.tmp", 0);
        r.ExcludedName = true;
        tracker.Add("1", "h", r, null, All, T);
        Assert.Null(tracker.Confirm("1", "h"));
    }

    [Fact]
    public void A_temporary_file_renamed_to_a_real_name_is_a_write_of_that_name()
    {
        var c = new UsnCorrelator { TakesContentAt = p => !p.EndsWith(".tmp") };
        c.AddRename(@"C:\d\~WRD0001.tmp", @"C:\d\doc.docx", T.AddSeconds(0.5));
        var r = Rec("Rename", @"C:\d\~WRD0001.tmp", 0);
        r.ExcludedName = true;
        c.Hold(r, T);
        c.CaughtUpUtc = T.AddSeconds(100);
        var w = Assert.Single(c.Release(T.AddSeconds(1)));
        Assert.Equal(("Write", @"C:\d\doc.docx", "doc.docx", @"C:\d"), (w.AccessType, w.FilePath, w.FileName, w.FolderPath));
        Assert.Null(w.NewPath);
    }

    [Theory]
    [InlineData(@"C:\d\other.tmp")]   // to another temporary name
    [InlineData(null)]                // new name not known
    public void A_temporary_file_renamed_to_a_name_that_is_not_recorded_leaves_nothing(string? newPath)
    {
        var c = new UsnCorrelator { TakesContentAt = p => !p.EndsWith(".tmp") };
        if (newPath != null) c.AddRename(@"C:\d\a.tmp", newPath, T.AddSeconds(0.5));
        var r = Rec("Rename", @"C:\d\a.tmp", 0);
        r.ExcludedName = true;
        c.Hold(r, T);
        c.CaughtUpUtc = T.AddSeconds(100);
        Assert.Empty(c.Release(T.AddSeconds(1)));
    }

    [Fact]
    public void A_temporary_rename_follows_the_Write_setting()
    {
        var r = Rec("Delete", @"C:\d\a.tmp", 0);
        r.ExcludedName = true;
        var onlyDelete = new DeleteTracker(_ => false);
        onlyDelete.Add("1", "h", r, null, new HashSet<string> { "Delete" }, T);
        Assert.Empty(onlyDelete.Expire(T, T.AddSeconds(5)));

        var r2 = Rec("Delete", @"C:\d\a.tmp", 0);
        r2.ExcludedName = true;
        var withWrite = new DeleteTracker(_ => false);
        withWrite.Add("1", "h", r2, null, new HashSet<string> { "Write" }, T);
        Assert.Single(withWrite.Expire(T, T.AddSeconds(5)));
    }

    // ---- Windows: empty files and truncations (no access is logged for them)

    private static UsnCorrelator Correlator() => new() { TakesUnexplainedAt = p => !p.EndsWith(".tmp") };

    // Both the journal and the Security log this far past T
    private static List<AccessRecord> At(UsnCorrelator c, double seconds)
    {
        c.CaughtUpUtc = T.AddSeconds(seconds);
        c.SecurityLogUtc = T.AddSeconds(seconds);
        return c.Release(T.AddSeconds(seconds));
    }

    [Fact]
    public void An_empty_file_is_recorded_as_created_by_an_unknown_user_once_no_write_can_explain_it()
    {
        var c = Correlator();
        c.AddCreate(@"C:\d\empty.txt", T);
        Assert.Empty(At(c, 20));                                        // a write may still come
        var r = Assert.Single(At(c, 40));
        Assert.Equal(("Create", @"C:\d\empty.txt", UsnCorrelator.UnknownUser), (r.AccessType, r.FilePath, r.UserName));
        Assert.Equal(T, r.AccessTime);
        Assert.Empty(At(c, 80));                                        // once
    }

    [Fact]
    public void A_file_emptied_by_overwriting_is_a_write_by_an_unknown_user()
    {
        var c = Correlator();
        c.AddTruncate(@"C:\d\a.txt", T);
        var r = Assert.Single(At(c, 40));
        Assert.Equal(("Write", UsnCorrelator.UnknownUser), (r.AccessType, r.UserName));
    }

    [Fact]
    public void A_create_or_truncation_explained_by_a_write_is_not_recorded_again()
    {
        var c = Correlator();
        c.AddCreate(@"C:\d\new.txt", T);
        c.AddTruncate(@"C:\d\old.txt", T);
        c.Hold(Rec("Write", @"C:\d\new.txt", 5), T.AddSeconds(5));
        c.Hold(Rec("Write", @"C:\d\old.txt", 5), T.AddSeconds(5));
        Assert.Equal(["Create", "Write"], At(c, 40).Select(r => r.AccessType));
    }

    [Fact]
    public void A_create_by_an_account_that_is_not_recorded_stays_unrecorded()
    {
        var c = Correlator();
        c.AddCreate(@"C:\d\by-system.txt", T);
        c.Claim(@"C:\d\by-system.txt", T.AddSeconds(1));                // its write, by SYSTEM
        c.AddCreate(@"C:\d\skip.tmp", T);                               // an excluded name
        Assert.Empty(At(c, 40));
    }

    [Fact]
    public void A_held_record_from_before_keeps_the_facts_after_it_waiting()
    {
        var c = Correlator();
        c.AddCreate(@"C:\d\a.txt", T.AddSeconds(10));
        c.Hold(Rec("Write", @"C:\d\b.txt", 0), T.AddSeconds(100));      // not ready: the journal is behind it
        c.CaughtUpUtc = T.AddSeconds(-10);
        c.SecurityLogUtc = T.AddSeconds(60);
        Assert.Empty(c.Release(T.AddSeconds(100)));
    }

    [Fact]
    public void An_audited_open_tells_who_created_or_emptied_the_file()
    {
        var c = Correlator();
        c.AddCreate(@"C:\d\empty.txt", T);
        c.AddOpen(@"C:\d\empty.txt", T.AddMilliseconds(-5), new AccessRecord { UserName = @"CORP\taro", ClientIp = "192.168.0.81", ClientMachine = "pc01", ServerName = "FS01" });
        c.AddCreate(@"C:\d\by-service.txt", T);
        c.AddOpen(@"C:\d\by-service.txt", T, null);                     // an excluded account opened it
        var r = Assert.Single(At(c, 40));
        Assert.Equal((@"CORP\taro", "192.168.0.81", "pc01", "FS01"), (r.UserName, r.ClientIp, r.ClientMachine, r.ServerName));
    }

    [Fact]
    public void Unexplained_facts_are_only_recorded_once_both_sources_are_past_them()
    {
        var c = Correlator();
        c.AddCreate(@"C:\d\a.txt", T);
        c.CaughtUpUtc = T.AddSeconds(100);
        c.SecurityLogUtc = T.AddSeconds(10);                            // the Security log is behind (catching up)
        Assert.Empty(c.Release(T.AddSeconds(100)));
        c.SecurityLogUtc = T.AddSeconds(100);
        Assert.Single(c.Release(T.AddSeconds(100)));
    }

    // ---- both: one write per save

    [Fact]
    public void Writes_of_one_file_by_one_user_within_two_seconds_are_one()
    {
        var m = new WriteMerger();
        Assert.True(m.ShouldRecord(Rec("Create", @"C:\d\a.txt", 0)));
        Assert.False(m.ShouldRecord(Rec("Write", @"C:\d\A.TXT", 1)));   // the same save
        Assert.True(m.ShouldRecord(Rec("Write", @"C:\d\a.txt", 1, user: "other")));
        Assert.True(m.ShouldRecord(Rec("Write", @"C:\d\b.txt", 1)));
        Assert.True(m.ShouldRecord(Rec("Read", @"C:\d\a.txt", 1)));
        Assert.True(m.ShouldRecord(Rec("Write", @"C:\d\a.txt", 2.5)));   // a later save
    }

    // ---- Linux (Samba): saves through temporary names

    private const string Prefix = @"CORP\taro|192.168.0.20|PC01|share|/srv/share|";

    private SambaAuditCollector Collector(string[]? types = null)
    {
        var collector = new SambaAuditCollector(new RemoteRecordSink(new AgentOutbox(_dir), NullLogger<RemoteRecordSink>.Instance),
            NullLogger<SambaAuditCollector>.Instance) { PathExists = _ => true };
        collector.UseSettings([("/srv/share/docs", types ?? ["Read", "Write", "Delete", "Permission"])], new RecordingSettings { MergeReadMinutes = 0 });
        return collector;
    }

    // Lines through ShouldKeep, then what is still held once its time is up
    private static List<AccessRecord> Feed(SambaAuditCollector c, params string[] lines)
    {
        var records = new List<AccessRecord>();
        var t = T;
        foreach (var line in lines)
        {
            records.AddRange(c.ExpireHeld(t, DateTime.UtcNow));
            if (c.ToRecord(Prefix + line, t) is { } r && c.ShouldKeep(r)) records.Add(r);
            t = t.AddMilliseconds(20);
        }
        records.AddRange(c.ExpireHeld(DateTime.MaxValue, DateTime.UtcNow));
        return records;
    }

    private static string Key(AccessRecord r) => $"{r.AccessType}:{r.FilePath}" + (r.NewPath != null ? ">" + r.NewPath : "");

    [Fact]
    public void An_Office_save_over_SMB_is_one_write_of_the_document()
    {
        var c = Collector();
        var records = Feed(c,
            "create_file|ok|0x120196|file|overwrite_if|/srv/share/docs/~$doc.docx",
            "create_file|ok|0x120196|file|overwrite_if|/srv/share/docs/~WRD0001.tmp",
            "renameat|ok|/srv/share/docs/doc.docx|/srv/share/docs/~WRL0001.tmp",
            "renameat|ok|/srv/share/docs/~WRD0001.tmp|/srv/share/docs/doc.docx",
            "unlinkat|ok|/srv/share/docs/~WRL0001.tmp",
            "unlinkat|ok|/srv/share/docs/~$doc.docx");
        Assert.Equal(["Write:/srv/share/docs/doc.docx"], records.Select(Key));
    }

    [Fact]
    public void A_rename_to_a_temporary_name_with_nothing_put_in_its_place_is_recorded_as_it_was()
    {
        var records = Feed(Collector(), "renameat|ok|/srv/share/docs/a.docx|/srv/share/docs/a.tmp");
        Assert.Equal(["Rename:/srv/share/docs/a.docx>/srv/share/docs/a.tmp"], records.Select(Key));
    }

    [Fact]
    public void A_rename_from_a_temporary_name_is_a_write_of_the_new_name()
    {
        var records = Feed(Collector(), "renameat|ok|/srv/share/docs/download.tmp|/srv/share/docs/report.pdf");
        Assert.Equal(["Write:/srv/share/docs/report.pdf"], records.Select(Key));
        Assert.Empty(Feed(Collector(["Read", "Delete"]), "renameat|ok|/srv/share/docs/x.tmp|/srv/share/docs/y.pdf"));
    }

    [Fact]
    public void A_rename_between_temporary_names_leaves_nothing()
    {
        Assert.Empty(Feed(Collector(), "renameat|ok|/srv/share/docs/a.tmp|/srv/share/docs/b.tmp"));
    }

    [Fact]
    public void Another_users_file_put_in_place_does_not_turn_a_rename_into_a_save()
    {
        var c = Collector();
        var records = new List<AccessRecord>();
        if (c.ToRecord(Prefix + "renameat|ok|/srv/share/docs/doc.docx|/srv/share/docs/~WRL0001.tmp", T) is { } r1) records.Add(r1);
        const string otherUser = @"CORP\hanako|192.168.0.21|PC02|share|/srv/share|";
        if (c.ToRecord(otherUser + "renameat|ok|/srv/share/docs/~WRD0002.tmp|/srv/share/docs/doc.docx", T.AddSeconds(1)) is { } r2) records.Add(r2);
        records.AddRange(c.ExpireHeld(DateTime.MaxValue, DateTime.UtcNow));
        Assert.Equal(["Write:/srv/share/docs/doc.docx", "Rename:/srv/share/docs/doc.docx>/srv/share/docs/~WRL0001.tmp"], records.Select(Key));
    }

    [Fact]
    public void Two_opens_for_writing_in_one_save_are_one_write()
    {
        var records = Feed(Collector(),
            "create_file|ok|0x120196|file|overwrite_if|/srv/share/docs/a.txt",
            "create_file|ok|0x120196|file|overwrite_if|/srv/share/docs/a.txt");
        Assert.Single(records);
    }
}
