using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileAccessMonitor.Tests;

public class DeniedEventTests
{
    private static readonly DateTime T0 = new(2026, 11, 3, 10, 0, 0, DateTimeKind.Utc);
    private static readonly HashSet<string> AllTypes = new(["Read", "Write", "Delete", "Permission"], StringComparer.OrdinalIgnoreCase);

    private static EventLogCollectorService Service(HashSet<string>? types = null, RecordingSettings? settings = null)
    {
        var service = new EventLogCollectorService(null!, NullLogger<EventLogCollectorService>.Instance,
            new ConfigurationBuilder().Build(), new DnsResolverService(NullLogger<DnsResolverService>.Instance));
        service.UseConfigForTest([(@"C:\data", types ?? AllTypes)], new RecordingRules(settings ?? new RecordingSettings()));
        return service;
    }

    private static EventLogCollectorService.RawEvent Event(int id, bool failure, string mask, string path = @"C:\data\a.txt",
        string user = "alice", string objectType = "File", string process = @"C:\Windows\explorer.exe", string? status = null)
    {
        var data = new Dictionary<string, string>
        {
            ["SubjectUserName"] = user,
            ["SubjectDomainName"] = "CORP",
            ["SubjectLogonId"] = "0x1234",
            ["ObjectType"] = objectType,
            ["ObjectName"] = path,
            ["AccessMask"] = mask,
            ["ProcessName"] = process,
        };
        if (status != null) data["Status"] = status;
        return new EventLogCollectorService.RawEvent(id, 1, T0, data, failure);
    }

    private static AccessRecord? Process(EventLogCollectorService s, EventLogCollectorService.RawEvent ev) =>
        s.ProcessEvent(ev, true, new HashSet<string>(StringComparer.OrdinalIgnoreCase));

    [Theory]
    [InlineData(0x120089L, "Read")]
    [InlineData(0x120116L, "Write")]
    [InlineData(0x10000L, "Delete")]
    [InlineData(0x1L, "Read")]
    [InlineData(0x80000000L, "Read")]
    [InlineData(0x40000000L, "Write")]
    public void Denied_type_comes_from_the_requested_mask(long mask, string expected) =>
        Assert.Equal(expected, EventLogCollectorService.ParseDeniedType(mask));

    [Theory]
    [InlineData(0x80L)]      // ReadAttributes
    [InlineData(0x40000L)]   // WRITE_DAC
    [InlineData(0x80000L)]   // WRITE_OWNER
    [InlineData(0x0L)]
    public void Denied_type_ignores_attribute_only_requests(long mask) =>
        Assert.Null(EventLogCollectorService.ParseDeniedType(mask));

    [Theory]
    [InlineData("0x40000")]   // WRITE_DAC granted
    [InlineData("0x80000")]   // WRITE_OWNER granted
    [InlineData("0xC0000")]
    public void Granted_permission_or_owner_change_makes_no_access_record(string mask)
    {
        Assert.Null(EventLogCollectorService.ParseAccessType(mask));
        Assert.Null(Process(Service(), Event(4663, false, mask)));
    }

    [Fact]
    public void Failed_open_for_read_is_a_denied_read()
    {
        var r = Process(Service(), Event(4656, true, "0x120089"));
        Assert.NotNull(r);
        Assert.True(r.Denied);
        Assert.Equal("Read", r.AccessType);
        Assert.Equal(@"CORP\alice", r.UserName);
        Assert.Equal(@"C:\data\a.txt", r.FilePath);
        Assert.False(r.IsFolder);
    }

    [Theory]
    [InlineData("0x120116", "Write")]
    [InlineData("0x10080", "Delete")]
    public void Failed_open_for_write_or_delete(string mask, string type)
    {
        var s = Service();
        // A refused delete is held briefly (it may be retried successfully), see the tests below
        var r = Process(s, Event(4656, true, mask)) ?? s.ExpireForTest(force: true).SingleOrDefault();
        Assert.Equal(type, r?.AccessType);
        Assert.True(r?.Denied);
    }

    [Fact]
    public void Successful_4656_is_ignored() =>
        Assert.Null(Process(Service(), Event(4656, false, "0x120089")));

    [Fact]
    public void Failure_with_another_status_is_ignored()
    {
        Assert.Null(Process(Service(), Event(4656, true, "0x120089", status: "0xC0000043")));
        Assert.NotNull(Process(Service(), Event(4656, true, "0x120089", status: "0xc0000022")));
        Assert.NotNull(Process(Service(), Event(4656, true, "0x120089", status: "-")));
    }

    [Fact]
    public void Denied_is_off_with_RecordDenied_false() =>
        Assert.Null(Process(Service(settings: new RecordingSettings { RecordDenied = false }), Event(4656, true, "0x120089")));

    [Fact]
    public void Denied_type_must_be_monitored_for_the_path()
    {
        var onlyWrite = Service(new HashSet<string>(["Write"], StringComparer.OrdinalIgnoreCase));
        Assert.Null(Process(onlyWrite, Event(4656, true, "0x120089")));
        Assert.NotNull(Process(onlyWrite, Event(4656, true, "0x120116")));
    }

    [Fact]
    public void Denied_folder_open_is_recorded_as_a_folder()
    {
        var dir = Path.Combine(Path.GetTempPath(), "fam-denied-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var service = new EventLogCollectorService(null!, NullLogger<EventLogCollectorService>.Instance,
                new ConfigurationBuilder().Build(), new DnsResolverService(NullLogger<DnsResolverService>.Instance));
            service.UseConfigForTest([(Path.GetTempPath().TrimEnd('\\'), AllTypes)], new RecordingRules(new RecordingSettings()));
            var r = Process(service, Event(4656, true, "0x1", dir));
            Assert.True(r?.IsFolder);
            Assert.True(r?.Denied);
        }
        finally { Directory.Delete(dir); }
    }

    [Fact]
    public void Alternate_data_stream_and_other_object_types_are_ignored()
    {
        Assert.Null(Process(Service(), Event(4656, true, "0x120089", @"C:\data\a.jpg:Zone.Identifier")));
        Assert.Null(Process(Service(), Event(4656, true, "0x120089", objectType: "Key")));
        Assert.Null(Process(Service(), Event(4656, true, "0x120089", @"C:\other\a.txt")));
    }

    [Fact]
    public void Excluded_process_user_and_file_are_ignored()
    {
        var settings = new RecordingSettings { ExcludeProcesses = ["avscan.exe"], ExcludeUsers = ["bob"] };
        var s = Service(settings: settings);
        Assert.Null(Process(s, Event(4656, true, "0x120089", process: @"C:\av\AVSCAN.EXE")));
        Assert.Null(Process(s, Event(4656, true, "0x120089", user: "bob")));
        Assert.Null(Process(s, Event(4656, true, "0x120089", @"C:\data\Thumbs.db")));
        Assert.NotNull(Process(s, Event(4656, true, "0x120089")));
    }

    [Fact]
    public void System_accounts_are_ignored() =>
        Assert.Null(Process(Service(), Event(4656, true, "0x120089", user: "SYSTEM")));

    [Fact]
    public void Denied_delete_is_recorded_when_no_successful_retry_follows()
    {
        var s = Service();
        Assert.Null(Process(s, Event(4656, true, "0x10000")));
        Assert.Empty(s.ExpireForTest(force: false));           // held for the confirm timeout
        var r = Assert.Single(s.ExpireForTest(force: true));
        Assert.Equal("Delete", r.AccessType);
        Assert.True(r.Denied);
    }

    // ReplaceFile (how File.Replace and many editors save) is refused DELETE access once, then gets it
    [Fact]
    public void Denied_delete_retried_successfully_by_the_same_user_is_dropped()
    {
        var s = Service();
        Assert.Null(Process(s, Event(4656, true, "0x10000")));
        Assert.Null(Process(s, Event(4663, false, "0x10000")));   // the successful DELETE access (pending in the tracker)
        Assert.DoesNotContain(s.ExpireForTest(force: true), r => r.Denied);
    }

    [Fact]
    public void Denied_delete_is_kept_when_another_user_or_file_succeeds()
    {
        var s = Service();
        Process(s, Event(4656, true, "0x10000"));
        Process(s, Event(4663, false, "0x10000", user: "bob"));
        Process(s, Event(4663, false, "0x10000", path: @"C:\data\b.txt"));
        Assert.Single(s.ExpireForTest(force: true), r => r.Denied);
    }

    private static AccessRecord Denied(string user, string path, string type, double seconds) => new()
    {
        UserName = user, FilePath = path, AccessType = type, Denied = true, AccessTime = T0.AddSeconds(seconds),
    };

    [Fact]
    public void Merger_records_retries_within_60_seconds_once()
    {
        var m = new EventLogCollectorService.DeniedMerger();
        Assert.True(m.ShouldRecord(Denied("a", @"C:\x\f.txt", "Read", 0)));
        Assert.False(m.ShouldRecord(Denied("a", @"C:\x\f.txt", "Read", 30)));
        Assert.False(m.ShouldRecord(Denied("A", @"C:\X\F.TXT", "Read", 85))); // window slides, case-insensitive
        Assert.True(m.ShouldRecord(Denied("a", @"C:\x\f.txt", "Read", 200)));
    }

    [Fact]
    public void Merger_keeps_user_path_and_type_apart()
    {
        var m = new EventLogCollectorService.DeniedMerger();
        Assert.True(m.ShouldRecord(Denied("a", @"C:\x\f.txt", "Read", 0)));
        Assert.True(m.ShouldRecord(Denied("b", @"C:\x\f.txt", "Read", 1)));
        Assert.True(m.ShouldRecord(Denied("a", @"C:\x\g.txt", "Read", 2)));
        Assert.True(m.ShouldRecord(Denied("a", @"C:\x\f.txt", "Write", 3)));
    }

    [Fact]
    public void Permission_event_needs_the_Permission_type_on_the_path()
    {
        var ev = new EventLogCollectorService.RawEvent(4670, 2, T0, new Dictionary<string, string>
        {
            ["SubjectUserName"] = "alice", ["SubjectDomainName"] = "CORP", ["SubjectLogonId"] = "0x1",
            ["ObjectType"] = "File", ["ObjectName"] = @"C:\data\a.txt", ["ProcessName"] = @"C:\Windows\explorer.exe",
            ["OldSd"] = "O:BAD:(A;;FA;;;SY)", ["NewSd"] = "O:BAD:(A;;FA;;;SY)(A;;0x1200a9;;;WD)",
        });
        var without = Service(new HashSet<string>(["Read", "Write", "Delete"], StringComparer.OrdinalIgnoreCase));
        Assert.Null(Process(without, ev));

        var r = Process(Service(), ev);
        Assert.Equal("Permission", r?.AccessType);
        Assert.False(r?.Denied);
        Assert.Contains("allow", r?.Detail);
        Assert.Contains("ReadAndExecute", r?.Detail);
    }
}
