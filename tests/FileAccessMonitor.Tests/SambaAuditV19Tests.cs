using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.Extensions.Logging.Abstractions;

#pragma warning disable CA1416 // the Samba collector is for Linux; these tests use its platform-neutral parts

namespace FileAccessMonitor.Tests;

// Samba audit lines of 1.9: refused accesses ("fail (...)"), file creation, rename destinations and
// permission changes. Lines are as Samba 4.19 / 4.23 write them (full_audit: "ok" or "fail (%s)").
public class SambaAuditV19Tests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "fam-samba19-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    private const string Prefix = @"CORP\taro|192.168.0.20|PC01|share|/srv/share|";
    private static readonly DateTime Time = new(2026, 11, 3, 1, 2, 3, DateTimeKind.Utc);

    private SambaAuditCollector Collector(string[] types, RecordingSettings? rules = null)
    {
        var collector = new SambaAuditCollector(new RemoteRecordSink(new AgentOutbox(_dir), NullLogger<RemoteRecordSink>.Instance),
            NullLogger<SambaAuditCollector>.Instance);
        collector.UseSettings([("/srv/share/docs", types)], rules ?? new RecordingSettings { MergeReadMinutes = 0 });
        return collector;
    }

    [Fact]
    public void Status_field_is_ok_or_fail_with_the_error_text()
    {
        var ok = AuditLine.Parse(Prefix + "create_file|ok|0x120089|file|open|/srv/share/docs/a.txt")!;
        Assert.True(ok.Ok);
        Assert.Equal("ok", ok.Status);

        var fail = AuditLine.Parse(Prefix + "create_file|fail (Permission denied)|0x120089|file|open|/srv/share/docs/a.txt")!;
        Assert.False(fail.Ok);
        Assert.Equal("fail (Permission denied)", fail.Status);
        Assert.Equal(["0x120089", "file", "open", "/srv/share/docs/a.txt"], fail.Args);
    }

    [Theory]
    [InlineData("connect|fail (Permission denied)|share")]                               // not in the failure list
    [InlineData("fset_nt_acl|fail (Permission denied)|docs/a.txt")]                      // permission changes: successes only
    [InlineData("create_file|maybe|0x120089|file|open|/srv/share/docs/a.txt")]           // not ok, not fail
    public void Failed_lines_of_other_operations_are_dropped(string rest) =>
        Assert.Null(AuditLine.Parse(Prefix + rest));

    [Theory]
    // read, write and delete refused (the access mask as the client asked for it)
    [InlineData("create_file|fail (Permission denied)|0x120089|file|open|/srv/share/docs/a.txt", "/srv/share/docs/a.txt", "Read", false)]
    [InlineData("create_file|fail (Permission denied)|0x12019f|file|open|/srv/share/docs/a.txt", "/srv/share/docs/a.txt", "Write", false)]
    [InlineData("create_file|fail (Permission denied)|0x110080|file|open|/srv/share/docs/a.txt", "/srv/share/docs/a.txt", "Delete", false)]
    [InlineData("create_file|fail (Permission denied)|0x100081|dir|open|/srv/share/docs/private", "/srv/share/docs/private", "Read", true)]
    [InlineData("create_file|fail (Operation not permitted)|0x12019f|file|open|docs/a.txt", "/srv/share/docs/a.txt", "Write", false)]
    [InlineData("unlinkat|fail (Permission denied)|/srv/share/docs/a.txt", "/srv/share/docs/a.txt", "Delete", false)]
    [InlineData("rmdir|fail (Permission denied)|/srv/share/docs/old", "/srv/share/docs/old", "Delete", true)]
    [InlineData("renameat|fail (Permission denied)|/srv/share/docs/a.txt|/srv/share/docs/b.txt", "/srv/share/docs/a.txt", "Rename", false)]
    [InlineData("create_file|fail (許可がありません)|0x120089|file|open|/srv/share/docs/a.txt", "/srv/share/docs/a.txt", "Read", false)] // Japanese smbd
    public void Refused_accesses_are_denied_records(string rest, string path, string type, bool folder)
    {
        var access = AuditInterpreter.Interpret(AuditLine.Parse(Prefix + rest)!)!;
        Assert.Equal((path, type, folder, true), (access.Path, access.Type, access.IsFolder, access.Denied));
    }

    [Theory]
    [InlineData("create_file|fail (No such file or directory)|0x120089|file|open|/srv/share/docs/desktop.ini")] // probe of a missing file
    [InlineData("create_file|fail (Device or resource busy)|0x12019f|file|open|/srv/share/docs/a.txt")]
    [InlineData("create_file|fail|0x120089|file|open|/srv/share/docs/a.txt")]                                    // no reason given
    [InlineData("create_file|fail (Permission denied)|0x100080|file|open|/srv/share/docs/a.txt")]                // attributes only
    [InlineData("unlinkat|fail (No such file or directory)|/srv/share/docs/a.txt")]
    [InlineData("renameat|fail (File exists)|/srv/share/docs/a.txt|/srv/share/docs/b.txt")]
    public void Other_failures_are_ignored(string rest) =>
        Assert.Null(AuditInterpreter.Interpret(AuditLine.Parse(Prefix + rest)!));

    [Theory]
    [InlineData("create_file|ok|0x12019f|file|create|/srv/share/docs/new.txt", "Create")]
    [InlineData("create_file|ok|0x100080|file|create|/srv/share/docs/new.txt", "Create")]   // touch: attributes only
    [InlineData("create_file|ok|0x12019f|file|overwrite_if|/srv/share/docs/new.txt", "Write")]
    [InlineData("create_file|ok|0x12019f|file|open_if|/srv/share/docs/new.txt", "Write")]
    [InlineData("create_file|ok|0x12019f|file|supersede|/srv/share/docs/new.txt", "Write")]
    [InlineData("create_file|ok|0x12019f|file|open|/srv/share/docs/new.txt", "Write")]
    public void A_file_made_by_the_call_is_a_create(string rest, string type) =>
        Assert.Equal(type, AuditInterpreter.Interpret(AuditLine.Parse(Prefix + rest)!)!.Type);

    [Fact]
    public void A_folder_made_by_the_call_is_not_a_create()
    {
        var access = AuditInterpreter.Interpret(AuditLine.Parse(Prefix + "create_file|ok|0x80|dir|create|/srv/share/docs/sub")!)!;
        Assert.Equal(("", true), (access.Type, access.IsFolder));
    }

    [Fact]
    public void Renames_carry_the_new_path()
    {
        var moved = AuditInterpreter.Interpret(AuditLine.Parse(Prefix + "renameat|ok|/srv/share/docs/a.txt|/srv/share/archive/a.txt")!)!;
        Assert.Equal(("/srv/share/docs/a.txt", "Rename", "/srv/share/archive/a.txt"), (moved.Path, moved.Type, moved.NewPath));

        var relative = AuditInterpreter.Interpret(AuditLine.Parse(Prefix + "rename|ok|docs/a.txt|docs/b.txt")!)!;
        Assert.Equal("/srv/share/docs/b.txt", relative.NewPath);

        // The folder Samba makes under a temporary name is a folder being made, not a rename
        var tmp = AuditInterpreter.Interpret(AuditLine.Parse(Prefix + "renameat|ok|/srv/share/docs/.::TMPNAME:D:756%65:sub|/srv/share/docs/sub")!)!;
        Assert.Equal(("", true, null), (tmp.Type, tmp.IsFolder, tmp.NewPath));
    }

    [Theory]
    [InlineData("fset_nt_acl|ok|docs/a.txt", "/srv/share/docs/a.txt", null)]
    [InlineData("fset_nt_acl|ok|/srv/share/docs/a.txt", "/srv/share/docs/a.txt", null)]
    [InlineData("sys_acl_set_fd|ok|docs/a.txt", "/srv/share/docs/a.txt", null)]
    [InlineData("fchmod|ok|docs/a.txt|644", "/srv/share/docs/a.txt", "mode 0644")]
    [InlineData("fchmod|ok|docs/a.txt|2775", "/srv/share/docs/a.txt", "mode 2775")]
    [InlineData("fchown|ok|docs/a.txt|1000|100", "/srv/share/docs/a.txt", "owner uid=1000 gid=100")]
    public void Permission_changes(string rest, string path, string? detail)
    {
        var access = AuditInterpreter.Interpret(AuditLine.Parse(Prefix + rest)!)!;
        Assert.Equal((path, "Permission", detail, false), (access.Path, access.Type, access.Detail, access.Denied));
    }

    [Fact]
    public void Denied_records_follow_the_setting_and_the_monitored_types()
    {
        var denied = Prefix + "create_file|fail (Permission denied)|0x120089|file|open|/srv/share/docs/secret.txt";
        var record = Collector(["Read"]).ToRecord(denied, Time)!;
        Assert.Equal(("Read", true, "/srv/share/docs/secret.txt", @"CORP\taro"), (record.AccessType, record.Denied, record.FilePath, record.UserName));

        Assert.Null(Collector(["Write", "Delete"]).ToRecord(denied, Time));                                     // Read not monitored
        Assert.Null(Collector(["Read"], new RecordingSettings { RecordDenied = false }).ToRecord(denied, Time)); // switched off
        Assert.Null(Collector(["Read"]).ToRecord(Prefix + "create_file|fail (No such file or directory)|0x120089|file|open|/srv/share/docs/x", Time));

        // A refused open of a folder is recorded (listing a forbidden folder), a successful one is not
        var folder = Collector(["Read"]).ToRecord(Prefix + "create_file|fail (Permission denied)|0x100081|dir|open|/srv/share/docs/private", Time)!;
        Assert.Equal(("Read", true, true), (folder.AccessType, folder.IsFolder, folder.Denied));
        Assert.Null(Collector(["Read"]).ToRecord(Prefix + "create_file|ok|0x100081|dir|open|/srv/share/docs/private", Time));
    }

    [Fact]
    public void Create_goes_with_the_write_type_and_rename_with_delete()
    {
        var create = Prefix + "create_file|ok|0x12019f|file|create|/srv/share/docs/new.txt";
        Assert.Equal("Create", Collector(["Write"]).ToRecord(create, Time)!.AccessType);
        Assert.Null(Collector(["Read", "Delete"]).ToRecord(create, Time));

        var rename = Prefix + "renameat|ok|/srv/share/docs/a.txt|/srv/share/docs/sub/a.txt";
        var record = Collector(["Delete"]).ToRecord(rename, Time)!;
        Assert.Equal(("Rename", "/srv/share/docs/sub/a.txt"), (record.AccessType, record.NewPath));
        Assert.Null(Collector(["Read", "Write"]).ToRecord(rename, Time));
    }

    [Fact]
    public void Permission_changes_are_recorded_for_paths_that_monitor_them()
    {
        var line = Prefix + "fset_nt_acl|ok|docs/report.txt";
        Assert.Null(Collector(["Read", "Write", "Delete"]).ToRecord(line, Time)); // existing paths opt in
        var record = Collector(["Permission"]).ToRecord(line, Time)!;
        Assert.Equal(("Permission", "/srv/share/docs/report.txt", null, false), (record.AccessType, record.FilePath, record.Detail, record.Denied));

        var chmod = Collector(["Permission"]).ToRecord(Prefix + "fchmod|ok|docs/report.txt|600", Time)!;
        Assert.Equal("mode 0600", chmod.Detail);
    }

    [Fact]
    public void Repeated_refusals_merge_within_a_minute_per_user_path_and_type()
    {
        var merger = new DeniedMerger(DeniedMerger.DeniedWindow);
        AccessRecord R(string user, string path, string type, int seconds) => new()
        {
            UserName = user, FilePath = path, AccessType = type, Denied = true, AccessTime = Time.AddSeconds(seconds),
        };
        Assert.True(merger.ShouldRecord(R("taro", "/a", "Read", 0)));
        Assert.False(merger.ShouldRecord(R("taro", "/a", "Read", 30)));
        Assert.False(merger.ShouldRecord(R("taro", "/a", "Read", 85)));   // sliding: 55 s after the last one
        Assert.True(merger.ShouldRecord(R("taro", "/a", "Read", 200)));
        Assert.True(merger.ShouldRecord(R("taro", "/a", "Write", 201)));  // another type
        Assert.True(merger.ShouldRecord(R("hanako", "/a", "Read", 202))); // another user
        Assert.True(merger.ShouldRecord(R("taro", "/A", "Read", 203)));   // paths are case-sensitive on Linux
    }

    [Fact]
    public void Permission_calls_of_one_command_merge_within_three_seconds()
    {
        var merger = new DeniedMerger(DeniedMerger.PermissionWindow);
        AccessRecord R(double seconds) => new()
        {
            UserName = "taro", FilePath = "/a", AccessType = "Permission", AccessTime = Time.AddSeconds(seconds),
        };
        Assert.True(merger.ShouldRecord(R(0)));
        Assert.False(merger.ShouldRecord(R(1)));
        Assert.False(merger.ShouldRecord(R(3.5)));
        Assert.True(merger.ShouldRecord(R(10)));
    }
}
