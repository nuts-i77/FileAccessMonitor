using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json.Nodes;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

// Scans a folder tree the test makes in the user's temp folder (ACLs of its own folders only)
public class PermissionWindowsScanTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "fam-perm-" + Guid.NewGuid().ToString("N"));
    private static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);
    private static readonly SecurityIdentifier Guests = new(WellKnownSidType.BuiltinGuestsSid, null);

    public PermissionWindowsScanTests()
    {
        if (!OperatingSystem.IsWindows()) return;
        Directory.CreateDirectory(Path.Combine(_root, "open", "inner"));
        Directory.CreateDirectory(Path.Combine(_root, "locked", "sub"));
        Directory.CreateDirectory(Path.Combine(_root, "plain"));
        File.WriteAllText(Path.Combine(_root, "open", "shared.txt"), "x");
        File.WriteAllText(Path.Combine(_root, "open", "plain.txt"), "x");
        File.WriteAllText(Path.Combine(_root, "plain", "a.txt"), "x");

        // An explicit Everyone entry, and a deny entry, on "open"
        var open = new DirectoryInfo(Path.Combine(_root, "open"));
        var sec = open.GetAccessControl();
        sec.AddAccessRule(new FileSystemAccessRule(Everyone, FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(Guests, FileSystemRights.Delete,
            InheritanceFlags.None, PropagationFlags.None, AccessControlType.Deny));
        open.SetAccessControl(sec);

        // "locked" does not inherit (the inherited entries are kept as explicit ones)
        var locked = new DirectoryInfo(Path.Combine(_root, "locked"));
        var lockedSec = locked.GetAccessControl();
        lockedSec.SetAccessRuleProtection(true, true);
        locked.SetAccessControl(lockedSec);

        // One file with its own entry
        var file = new FileInfo(Path.Combine(_root, "open", "shared.txt"));
        var fileSec = file.GetAccessControl();
        fileSec.AddAccessRule(new FileSystemAccessRule(Everyone, FileSystemRights.ReadAndExecute, AccessControlType.Allow));
        file.SetAccessControl(fileSec);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }

    private List<ViewRow> Scan(PermissionScanOptions? options = null)
    {
        var result = PermissionScanWindows.Scan(_root, options ?? new PermissionScanOptions(), CancellationToken.None);
        return PermissionReportView.Rows(PermissionResultTests.Report(result, "TEST", _root));
    }

    [Fact]
    public void Lists_the_root_and_the_objects_that_do_not_just_inherit()
    {
        if (!OperatingSystem.IsWindows()) return;
        var rows = Scan();
        Assert.Equal(["", "locked", "open", @"open\shared.txt"], rows.OrderBy(r => r.Rel, StringComparer.OrdinalIgnoreCase).Select(r => r.Rel).ToArray());
        Assert.DoesNotContain(rows, r => r.Rel.StartsWith("plain") || r.Rel == @"open\inner" || r.Rel == @"locked\sub");
    }

    [Fact]
    public void The_root_lists_its_inherited_entries_too()
    {
        if (!OperatingSystem.IsWindows()) return;
        var root = Scan().Single(r => r.Rel == "");
        Assert.NotEmpty(root.Aces);
        Assert.True(root.IsFolder);
        Assert.False(root.InheritanceBroken);
        Assert.NotNull(root.Owner);
    }

    [Fact]
    public void An_explicit_everyone_entry_is_found_and_flagged()
    {
        if (!OperatingSystem.IsWindows()) return;
        var open = Scan().Single(r => r.Rel == "open");
        var everyone = open.Aces.Single(a => a.Sid == "S-1-1-0" && a.Kind == "allow");
        Assert.Equal(("modify", 7, "everyone", "high"), (PermissionContract.LevelCode(everyone.Level), everyone.Scope, everyone.Broad, everyone.Severity));
        Assert.Equal("high", open.Severity);
        Assert.All(open.Aces, a => Assert.NotEqual("", a.Principal)); // names or SID text, never empty
    }

    [Fact]
    public void A_deny_entry_is_listed_with_kind_deny()
    {
        if (!OperatingSystem.IsWindows()) return;
        var deny = Scan().Single(r => r.Rel == "open").Aces.Single(a => a.Kind == "deny");
        Assert.Equal(("S-1-5-32-546", "guests", 4, (string?)null), (deny.Sid, deny.Broad, deny.Level, deny.Severity));
        Assert.Equal(1, deny.Scope); // this folder only
    }

    [Fact]
    public void A_folder_that_does_not_inherit_is_marked()
    {
        if (!OperatingSystem.IsWindows()) return;
        var locked = Scan().Single(r => r.Rel == "locked");
        Assert.True(locked.InheritanceBroken);
        Assert.NotEmpty(locked.Aces); // the copied entries are now its own
    }

    [Fact]
    public void A_file_with_its_own_entry_is_listed_and_one_without_is_not()
    {
        if (!OperatingSystem.IsWindows()) return;
        var rows = Scan();
        var file = rows.Single(r => r.Rel == @"open\shared.txt");
        Assert.False(file.IsFolder);
        Assert.Equal(1, file.Aces.Single(a => a.Sid == "S-1-1-0").Scope);
        Assert.DoesNotContain(rows, r => r.Rel == @"open\plain.txt");
    }

    [Fact]
    public void Files_are_left_out_when_not_asked_for()
    {
        if (!OperatingSystem.IsWindows()) return;
        var rows = Scan(new PermissionScanOptions(IncludeFiles: false));
        Assert.DoesNotContain(rows, r => !r.IsFolder);
        Assert.Contains(rows, r => r.Rel == "open");
    }

    [Fact]
    public void Limits_truncate_and_say_which()
    {
        if (!OperatingSystem.IsWindows()) return;
        var folders = PermissionScanWindows.Scan(_root, new PermissionScanOptions(MaxFolders: 2), CancellationToken.None);
        Assert.Equal(("folders", true, 2), (folders["limit"]!.GetValue<string>(), folders["truncated"]!.GetValue<bool>(), folders["folders"]!.GetValue<int>()));

        var files = PermissionScanWindows.Scan(_root, new PermissionScanOptions(MaxFiles: 1), CancellationToken.None);
        Assert.Equal("files", files["limit"]!.GetValue<string>());

        var depth = PermissionScanWindows.Scan(_root, new PermissionScanOptions(MaxDepth: 0), CancellationToken.None);
        Assert.Equal(("depth", 1), (depth["limit"]!.GetValue<string>(), depth["folders"]!.GetValue<int>()));
    }

    [Fact]
    public void A_junction_is_not_followed()
    {
        if (!OperatingSystem.IsWindows()) return;
        var link = Path.Combine(_root, "loop");
        // A directory symlink needs a privilege; a junction does not (mklink /J)
        var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{_root}\"")
            { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        using (var p = System.Diagnostics.Process.Start(psi)!) { p.WaitForExit(); if (p.ExitCode != 0) return; }
        try
        {
            var result = PermissionScanWindows.Scan(_root, new PermissionScanOptions(), CancellationToken.None);
            Assert.False(result["truncated"]!.GetValue<bool>());
            Assert.DoesNotContain(PermissionReportView.Rows(PermissionResultTests.Report(result, "TEST", _root)), r => r.Rel.StartsWith("loop"));
            Assert.Equal(6, result["folders"]!.GetValue<int>()); // root, open, open\inner, locked, locked\sub, plain
        }
        finally
        {
            Directory.Delete(link); // removes the junction only
        }
    }

    [Fact]
    public void A_cancelled_scan_stops()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.Throws<OperationCanceledException>(() => PermissionScanWindows.Scan(_root, new PermissionScanOptions(), cts.Token));
    }

    [Fact]
    public void The_result_has_the_documented_shape()
    {
        if (!OperatingSystem.IsWindows()) return;
        var result = PermissionScanWindows.Scan(_root, new PermissionScanOptions(), CancellationToken.None);
        Assert.Equal(("windows", _root), (result["os"]!.GetValue<string>(), result["root"]!.GetValue<string>()));
        Assert.Equal(6, result["folders"]!.GetValue<int>());
        Assert.Equal(3, result["files"]!.GetValue<int>());
        Assert.IsType<JsonArray>(result["principals"]);
        Assert.Null(result["shares"]); // Linux only
        Assert.True(DateTime.TryParse(result["scannedAt"]!.GetValue<string>(), out _));
    }
}
