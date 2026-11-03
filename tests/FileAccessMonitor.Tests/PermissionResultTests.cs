using System.Text.Json.Nodes;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class PermissionResultTests
{
    internal static StoredPermissionReport Report(JsonObject result, string server = "FS01", string root = @"D:\Share") => new()
    {
        Server = server, Root = root, Os = result["os"]?.GetValue<string>() ?? "windows", ScannedAt = new DateTime(2026, 11, 3, 1, 0, 0, DateTimeKind.Utc),
        Result = result,
    };

    [Fact]
    public void Builder_output_reads_back_as_rows()
    {
        var b = new PermissionResultBuilder("windows", @"D:\Share", new PermissionScanOptions());
        var everyone = b.Principal("Everyone", "S-1-1-0");
        var admins = b.Principal(@"BUILTIN\Administrators", "S-1-5-32-544");
        Assert.Equal(everyone, b.Principal("Everyone", "S-1-1-0")); // one entry per principal
        b.CountFolder();
        b.AddRow("", PermissionContract.FlagFolder | PermissionContract.FlagExplicit, admins,
            [new PermissionAce(admins, 0, 31, 7), new PermissionAce(everyone, 0, 17, 7)]);
        b.CountFolder();
        b.AddRow(@"Docs\Sub", PermissionContract.FlagFolder | PermissionContract.FlagInheritanceBroken, -1,
            [new PermissionAce(everyone, 1, 2, 3)]);
        b.AddError("D:\\Share\\x: not readable");

        var rows = PermissionReportView.Rows(Report(b.Build()));
        Assert.Equal(2, rows.Count);
        Assert.Equal(@"D:\Share", rows[0].Path);
        Assert.Equal(@"BUILTIN\Administrators", rows[0].Owner);
        Assert.Equal("medium", rows[0].Severity); // Everyone may read
        Assert.Equal((@"D:\Share\Docs\Sub", 2, true), (rows[1].Path, rows[1].Depth, rows[1].InheritanceBroken));
        var deny = rows[1].Aces.Single();
        Assert.Equal(("deny", "Write", "This folder and subfolders", "everyone", (string?)null), (deny.Kind, deny.LevelLabel, deny.ScopeLabel, deny.Broad, deny.Severity));
    }

    [Fact]
    public void Mask_limited_linux_entry_keeps_the_level_before_the_mask()
    {
        var b = new PermissionResultBuilder("linux", "/srv/share", new PermissionScanOptions());
        var u = b.Principal("user:nobody", null);
        b.AddRow("d", 1 | 16, -1, [new PermissionAce(u, 0, 1, 1, 17), new PermissionAce(u, 0, 3, 1, 3)]);
        var aces = PermissionReportView.Rows(Report(b.Build(), "CT115", "/srv/share")).Single().Aces;
        Assert.Equal([17, null], aces.Select(a => a.LevelBeforeMask).ToArray()); // not stored when equal
    }

    [Fact]
    public void Limits_set_truncated_and_the_first_one_wins()
    {
        var b = new PermissionResultBuilder("windows", @"D:\Share", new PermissionScanOptions());
        b.Truncate("files");
        b.Truncate("time");
        var result = b.Build();
        Assert.True(result["truncated"]!.GetValue<bool>());
        Assert.Equal("files", result["limit"]!.GetValue<string>());
    }

    [Fact]
    public void Rows_stop_at_the_cap_and_say_so()
    {
        var b = new PermissionResultBuilder("windows", @"D:\Share", new PermissionScanOptions());
        for (var i = 0; i < PermissionContract.MaxRows + 5; i++) b.AddRow($"f{i}", 0, -1, []);
        Assert.Equal(PermissionContract.MaxRows, b.Rows);
        Assert.Equal("rows", b.Build()["limit"]!.GetValue<string>());
    }

    [Fact]
    public void Errors_are_capped()
    {
        var b = new PermissionResultBuilder("windows", @"D:\Share", new PermissionScanOptions());
        for (var i = 0; i < 250; i++) b.AddError("e" + i);
        Assert.Equal(PermissionContract.MaxErrors, b.Build()["errors"]!.AsArray().Count);
    }

    [Fact]
    public void A_row_stays_within_the_size_budget()
    {
        // The design counts on 60-120 bytes per row
        var b = new PermissionResultBuilder("windows", @"D:\Share", new PermissionScanOptions());
        var users = b.Principal(@"BUILTIN\Users", "S-1-5-32-545");
        var admins = b.Principal(@"BUILTIN\Administrators", "S-1-5-32-544");
        for (var i = 0; i < 5000; i++)
            b.AddRow($@"Projects\Team{i % 50}\Folder{i}", 1 | 8, -1, [new PermissionAce(users, 0, 23, 7), new PermissionAce(admins, 0, 31, 7)]);
        var bytes = b.Build().ToJsonString().Length;
        Assert.InRange(bytes / 5000, 40, 140);
    }

    [Fact]
    public void Sizes_are_clamped_to_the_hard_maxima()
    {
        var o = PermissionContract.Clamp(new PermissionScanOptions(1_000_000, 10_000_000, 500, true, 100_000));
        Assert.Equal((20_000, 200_000, 32, 900), (o.MaxFolders, o.MaxFiles, o.MaxDepth, o.TimeLimitSeconds));
        var small = PermissionContract.Clamp(new PermissionScanOptions(0, -1, -1, false, 0));
        Assert.Equal((1, 0, 0, 5), (small.MaxFolders, small.MaxFiles, small.MaxDepth, small.TimeLimitSeconds));
    }

    [Fact]
    public void Job_arguments_round_trip_and_defaults_fill_the_gaps()
    {
        var o = new PermissionScanOptions(100, 200, 3, false, 60);
        Assert.Equal(o, PermissionContract.OptionsFrom(PermissionContract.ToArgs(@"D:\Share", o)));
        Assert.Equal(@"D:\Share", PermissionContract.ToArgs(@"D:\Share", o)["path"]!.GetValue<string>());
        Assert.Equal(new PermissionScanOptions(), PermissionContract.OptionsFrom(new JsonObject { ["path"] = "/srv" }));
    }

    [Fact]
    public void Absolute_paths_use_the_roots_separator()
    {
        Assert.Equal(@"D:\Share\a\b", PermissionContract.Absolute(@"D:\Share", @"a\b"));
        Assert.Equal(@"D:\a", PermissionContract.Absolute(@"D:\", "a"));
        Assert.Equal("/srv/share/a/b", PermissionContract.Absolute("/srv/share", "a/b"));
        Assert.Equal("/srv/share", PermissionContract.Absolute("/srv/share", ""));
    }

    [Fact]
    public void Tree_order_puts_children_after_their_parent_and_folders_first()
    {
        var b = new PermissionResultBuilder("windows", @"D:\Share", new PermissionScanOptions());
        foreach (var (rel, folder) in new[] { ("z.txt", false), ("b", true), (@"b\c", true), (@"b\a.txt", false), ("a", true), (@"b-x", true), ("", true) })
            b.AddRow(rel, folder ? 1 : 0, -1, []);
        var rows = PermissionReportView.Rows(Report(b.Build()));
        rows.Sort(PermissionReportView.TreeOrder(@"D:\Share"));
        Assert.Equal(["", "a", "b", @"b\c", @"b\a.txt", "b-x", "z.txt"], rows.Select(r => r.Rel).ToArray());
    }

    [Fact]
    public void Broad_rows_respect_the_scope_and_list_guest_shares()
    {
        var b = new PermissionResultBuilder("linux", "/srv/share", new PermissionScanOptions());
        var other = b.Principal("other", null);
        var taro = b.Principal("user:taro", null);
        b.AddRow("", 1, -1, [new PermissionAce(taro, 0, 31, 1), new PermissionAce(other, 0, 17, 1)]);
        b.AddRow("docs", 1, -1, [new PermissionAce(other, 0, 23, 1)]);
        b.SetShares(new JsonArray(new JsonObject { ["name"] = "share", ["path"] = "/srv/share", ["guestOk"] = true, ["readOnly"] = false }));
        var report = Report(b.Build(), "CT115", "/srv/share");

        var all = PermissionReportView.BroadRows(report, null);
        Assert.Equal(3, all.Count);
        Assert.Contains(all, r => r.Kind == "guestShare" && r.Severity == "high");
        Assert.Contains(all, r => r.Path == "/srv/share/docs" && r.Severity == "high" && r.Level == "Modify");
        Assert.Contains(all, r => r.Path == "/srv/share" && r.Principal == "other" && r.Severity == "medium");

        var scoped = PermissionReportView.BroadRows(report, [new ScopeEntry("CT115", "/srv/share/docs")]);
        Assert.Equal(["/srv/share/docs"], scoped.Select(r => r.Path).ToArray());
        Assert.Empty(PermissionReportView.BroadRows(report, [new ScopeEntry("OTHER", "/srv/share")]));
    }
}
