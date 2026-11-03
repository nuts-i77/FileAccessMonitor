using System.Security.Principal;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class PermissionChangeTests
{
    // SIDs as text keep the expected strings independent of the machine
    private static string Describe(string oldSddl, string newSddl) =>
        PermissionChange.Describe(oldSddl, newSddl, sid => sid.Value)!;

    [Fact]
    public void Added_allow_entry()
    {
        var text = Describe("O:BAD:PAI(A;OICI;FA;;;SY)", "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;WD)");
        Assert.Equal("+ allow S-1-1-0: ReadAndExecute", text);
    }

    [Fact]
    public void Removed_deny_entry()
    {
        var text = Describe("O:BAD:(D;;FA;;;WD)(A;;FA;;;SY)", "O:BAD:(A;;FA;;;SY)");
        Assert.Equal("- deny S-1-1-0: FullControl", text);
    }

    [Fact]
    public void Changed_rights_are_a_removal_and_an_addition()
    {
        var text = Describe("D:(A;;0x1301bf;;;BU)", "D:(A;;0x1f01ff;;;BU)");
        Assert.Equal("- allow S-1-5-32-545: Modify\n+ allow S-1-5-32-545: FullControl", text);
    }

    [Theory]
    [InlineData("0x120089", "Read")]
    [InlineData("0x100116", "Write")]
    [InlineData("0x20", "0x20")]
    public void Rights_names(string rights, string expected) =>
        Assert.Equal("+ allow S-1-1-0: " + expected, Describe("D:(A;;FA;;;SY)", $"D:(A;;FA;;;SY)(A;;{rights};;;WD)"));

    [Fact]
    public void Owner_change()
    {
        var text = Describe("O:BAD:(A;;FA;;;SY)", "O:SYD:(A;;FA;;;SY)");
        Assert.Equal("owner: S-1-5-32-544 -> S-1-5-18", text);
    }

    [Fact]
    public void Inheritance_toggle()
    {
        Assert.Equal("inheritance: enabled", Describe("D:P(A;;FA;;;SY)", "D:AI(A;;FA;;;SY)"));
        Assert.Equal("inheritance: disabled", Describe("D:AI(A;;FA;;;SY)", "D:P(A;;FA;;;SY)"));
    }

    [Fact]
    public void Propagation_suffix_only_when_not_the_default()
    {
        Assert.Equal("+ allow S-1-1-0: Read", Describe("D:(A;;FA;;;SY)", "D:(A;;FA;;;SY)(A;OICI;0x120089;;;WD)"));
        Assert.Equal("+ allow S-1-1-0: Read (this folder and subfolders)",
            Describe("D:(A;;FA;;;SY)", "D:(A;;FA;;;SY)(A;CI;0x120089;;;WD)"));
        Assert.Equal("+ allow S-1-1-0: Read (subfolders and files only)",
            Describe("D:(A;;FA;;;SY)", "D:(A;;FA;;;SY)(A;OICIIO;0x120089;;;WD)"));
    }

    [Fact]
    public void Only_inherited_entries_changed()
    {
        var r = PermissionChange.Analyze("D:AI(A;ID;FA;;;SY)", "D:AI(A;ID;FA;;;SY)(A;ID;0x120089;;;WD)", sid => sid.Value);
        Assert.NotNull(r);
        Assert.Equal("inherited permissions changed", r.Text);
        Assert.False(r.Explicit);
    }

    [Fact]
    public void Explicit_change_is_marked_explicit()
    {
        var r = PermissionChange.Analyze("D:(A;;FA;;;SY)", "D:(A;;FA;;;SY)(A;;0x120089;;;WD)", sid => sid.Value);
        Assert.True(r?.Explicit);
    }

    [Fact]
    public void Identical_or_equivalent_descriptors_give_nothing()
    {
        Assert.Null(PermissionChange.Describe("O:BAD:(A;;FA;;;SY)", "O:BAD:(A;;FA;;;SY)"));
        // only the auto-inherited marker differs: nobody gained or lost access
        Assert.Null(PermissionChange.Describe("D:(A;;FA;;;SY)", "D:AI(A;;FA;;;SY)"));
        Assert.Null(PermissionChange.Describe(null, null));
        Assert.Null(PermissionChange.Describe("", ""));
    }

    [Fact]
    public void Reordered_entries_are_not_a_change() =>
        Assert.Null(PermissionChange.Describe("D:(A;;FA;;;SY)(A;;FA;;;BA)", "D:(A;;FA;;;BA)(A;;FA;;;SY)"));

    [Fact]
    public void Unreadable_old_descriptor_still_reports_a_change()
    {
        Assert.Equal("permissions changed", PermissionChange.Describe("garbage", "D:(A;;FA;;;SY)"));
        Assert.Equal("permissions changed", PermissionChange.Describe("", "D:(A;;FA;;;SY)"));
    }

    [Fact]
    public void Long_text_is_truncated_to_2000_characters()
    {
        var aces = string.Concat(Enumerable.Range(1000, 100).Select(i => $"(A;;FA;;;S-1-5-21-1-2-3-{i})"));
        var text = Describe("D:(A;;FA;;;SY)", "D:(A;;FA;;;SY)" + aces);
        Assert.Equal(PermissionChange.MaxLength, text.Length);
        Assert.EndsWith("...", text);
    }

    [Fact]
    public void Unresolvable_sid_falls_back_to_the_sid_string()
    {
        var sid = "S-1-5-21-1111-2222-3333-4444";
        var text = PermissionChange.Describe("D:(A;;FA;;;SY)", $"D:(A;;FA;;;SY)(A;;FA;;;{sid})");
        Assert.Equal($"+ allow {sid}: FullControl", text);
    }

    [Fact]
    public void Well_known_sid_is_translated_by_default()
    {
        var text = PermissionChange.Describe("D:(A;;FA;;;SY)", "D:(A;;FA;;;SY)(A;;FA;;;WD)");
        Assert.Equal("+ allow Everyone: FullControl", text);
        _ = new SecurityIdentifier("S-1-1-0");
    }

    private static readonly DateTime T = new(2026, 11, 3, 10, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Merger_drops_inherited_only_children_after_the_parent()
    {
        var m = new PermissionMerger();
        Assert.True(m.ShouldRecord("0x1", @"C:\data\dir", T, isExplicit: true));
        Assert.False(m.ShouldRecord("0x1", @"C:\data\dir\sub\a.txt", T.AddSeconds(1), isExplicit: false));
        Assert.False(m.ShouldRecord("0x1", @"C:\DATA\dir\b.txt", T.AddSeconds(9), isExplicit: false));
        Assert.True(m.ShouldRecord("0x1", @"C:\data\dir\c.txt", T.AddSeconds(11), isExplicit: false)); // too late: not part of it
    }

    [Fact]
    public void Merger_keeps_explicit_child_changes_and_other_sessions()
    {
        var m = new PermissionMerger();
        Assert.True(m.ShouldRecord("0x1", @"C:\data\dir", T, true));
        Assert.True(m.ShouldRecord("0x1", @"C:\data\dir\a.txt", T.AddSeconds(1), true));
        Assert.True(m.ShouldRecord("0x2", @"C:\data\dir\b.txt", T.AddSeconds(1), false));
    }

    [Fact]
    public void Merger_records_the_same_path_once_within_2_seconds()
    {
        var m = new PermissionMerger();
        Assert.True(m.ShouldRecord("0x1", @"C:\data\a.txt", T, true));
        Assert.False(m.ShouldRecord("0x1", @"C:\data\A.TXT", T.AddSeconds(1.5), true));
        Assert.True(m.ShouldRecord("0x1", @"C:\data\a.txt", T.AddSeconds(5), true));
    }
}
