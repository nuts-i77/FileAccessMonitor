using System.Text.Json;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class UsnJournalStatusTests
{
    [Theory]
    [InlineData(@"e:\share", "E:")]
    [InlineData(@"D:\", "D:")]
    [InlineData(@"\\fs\share", null)]
    [InlineData("/srv/share", null)]
    [InlineData("", null)]
    public void DriveOf(string path, string? drive) => Assert.Equal(drive, UsnJournalStatus.DriveOf(path));

    [Fact]
    public void The_volume_is_opened_as_a_device_path()
    {
        if (!OperatingSystem.IsWindows()) return;
        Assert.Equal(@"\\.\E:", UsnJournalReader.DevicePath("E:"));
    }

    [Fact]
    public void For_finds_the_drive_of_a_folder_or_a_network_folder_itself()
    {
        var list = new List<JournalVolume>
        {
            new("E:", JournalStates.On, "ReFS"),
            new(@"\\fs\share", JournalStates.Network),
        };
        Assert.Equal("ReFS", UsnJournalStatus.For(list, @"e:\FamTest\sub")!.Format);
        Assert.Equal(JournalStates.Network, UsnJournalStatus.For(list, @"\\FS\share")!.State);
        Assert.Null(UsnJournalStatus.For(list, @"D:\Share"));
        Assert.Null(UsnJournalStatus.For(null, @"E:\x"));
    }

    [Fact]
    public void Clean_drops_unknown_states_duplicates_and_long_strings()
    {
        var cleaned = UsnJournalStatus.Clean(
        [
            new("E:", JournalStates.Off, "ReFS"),
            new("e:", JournalStates.On, "ReFS"),       // the same drive again
            new("F:", "made-up"),                       // not a state
            new("", JournalStates.On),
            new(new string('x', 300), JournalStates.Network),
            new("G:", JournalStates.Unsupported, new string('F', 40)), // format too long: dropped, entry kept
            null,
        ])!;
        Assert.Equal(["E:", "G:"], cleaned.Select(v => v.Volume));
        Assert.Equal(JournalStates.Off, cleaned[0].State);
        Assert.Null(cleaned[1].Format);
        Assert.Null(UsnJournalStatus.Clean(null));
    }

    [Fact]
    public void Clean_keeps_at_most_64_entries()
    {
        var many = Enumerable.Range(0, 100).Select(i => new JournalVolume($@"\\fs\share{i}", JournalStates.Network));
        Assert.Equal(64, UsnJournalStatus.Clean(many)!.Count);
    }

    [Fact]
    public void Agent_states_are_kept_per_agent_and_cleared_by_an_agent_that_does_not_say()
    {
        var states = new AgentJournalStates();
        states.Set("a1", [new("E:", JournalStates.On, "NTFS")]);
        Assert.Single(states.Get("a1")!);
        Assert.Null(states.Get("a2"));
        states.Set("a1", null); // an older agent (or Linux) leaves it out
        Assert.Null(states.Get("a1"));
    }

    // An agent of 1.13.1 sends the list in its heartbeat; servers before 1.13.1 ignore the field, and an
    // agent before 1.13.1 leaves it out
    [Fact]
    public void Heartbeat_carries_the_list_as_json()
    {
        var req = new HeartbeatRequest("1.13.1", 0, true, "Windows Server 2025", false, 0,
            [new JournalVolume("E:", JournalStates.On, "ReFS")]);
        var json = JsonSerializer.Serialize(req, JsonSerializerOptions.Web);
        Assert.Contains("\"journals\":[{\"volume\":\"E:\",\"state\":\"on\",\"format\":\"ReFS\"}]", json);
        var back = JsonSerializer.Deserialize<HeartbeatRequest>(json, JsonSerializerOptions.Web)!;
        Assert.Equal("ReFS", back.Journals![0].Format);

        var old = JsonSerializer.Deserialize<HeartbeatRequest>("{\"version\":\"1.13.0\",\"outboxCount\":0}", JsonSerializerOptions.Web)!;
        Assert.Null(old.Journals);
    }

    [Fact]
    public void Collector_state_keeps_the_cleaned_list_of_its_heartbeat()
    {
        var state = new LocalCollectorState();
        Assert.Null(state.Journals);
        state.Heartbeat(new HeartbeatRequest("1.13.1", Journals: [new("E:", JournalStates.Off, "ReFS"), new("E:", JournalStates.On)]), DateTime.UtcNow);
        Assert.Equal(JournalStates.Off, Assert.Single(state.Journals!).State);
    }
}

public class UsnJournalCreateTests
{
    [Fact]
    public void WithOn_marks_the_drive_as_on_and_keeps_the_others()
    {
        var list = UsnJournalStatus.WithOn([new("E:", JournalStates.Off, "ReFS"), new("D:", JournalStates.On, "NTFS")], "e:", "ReFS");
        Assert.Equal(2, list.Count);
        Assert.Equal(JournalStates.On, list.Single(v => v.Volume.Equals("E:", StringComparison.OrdinalIgnoreCase)).State);
        Assert.Equal("ReFS", list.Single(v => v.State == JournalStates.On && v.Volume.StartsWith('e')).Format);
        Assert.Single(UsnJournalStatus.WithOn(null, "E:", null));
    }

    // The size is the one the documentation and the GUI show for the fsutil command
    [Fact]
    public void The_created_journal_has_the_documented_size()
    {
        Assert.Equal(33554432UL, UsnJournalReader.CreateMaximumSize);
        Assert.Equal(8388608UL, UsnJournalReader.CreateAllocationDelta);
    }

    [Theory]
    [InlineData("journal.created")]
    [InlineData("journal.exists")]
    [InlineData("journal.notOff")]
    [InlineData("journal.unknown")]
    [InlineData("journal.notWindows")]
    [InlineData("journal.unsupported")]
    [InlineData("journal.failed")]
    public void Messages_exist_in_both_languages(string key)
    {
        Assert.True(Messages.AllEn.ContainsKey(key));
        Assert.True(Messages.AllJa.ContainsKey(key));
    }
}

public class JournalReportingAgentTests
{
    [Theory]
    [InlineData("Windows Server 2025 Standard", "1.13.1", true)]
    [InlineData("Windows 11 Pro", "1.13.1-rc4", true)]
    [InlineData("Windows Server 2022", "1.14.0", true)]
    [InlineData("Windows Server 2022", "0.0.0", true)]     // a local build
    [InlineData("Windows Server 2022", "1.13.0", false)]   // does not report: nothing is shown, not "being checked"
    [InlineData("Ubuntu 24.04 LTS", "1.13.1", false)]
    [InlineData(null, "1.13.1", false)]
    public void Only_windows_agents_from_1_13_1_report_journals(string? os, string version, bool reports) =>
        Assert.Equal(reports, FileAccessMonitor.Controllers.SettingsController.ReportsJournals(os, version));
}
