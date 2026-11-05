using FileAccessMonitor.Models;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

// The data of a report against a seeded database
public class ReportBuilderTests
{
    private static readonly DateTime Slot = ReportTestHost.Monday;   // Mon 2026-11-02 09:00 UTC; the period is the week before
    private static DateTime In(double days) => Slot.AddDays(-7).AddDays(days);                // inside the period

    private static ReportTestHost Seeded()
    {
        var host = new ReportTestHost();
        // in the period
        host.Access("FS01", @"D:\Share\Sales\a.xlsx", "Read", "alice", In(1));
        host.Access("FS01", @"D:\Share\Sales\a.xlsx", "Read", "alice", In(2));
        host.Access("FS01", @"D:\Share\Sales\a.xlsx", "Write", "bob", In(2));
        host.Access("FS01", @"D:\Share\HR\pay.xlsx", "Read", "carol", In(3));
        host.Access("FS01", @"D:\Share\HR\pay.xlsx", "Delete", "carol", In(3));
        host.Access("FS01", @"D:\Share\HR", "Permission", "admin", In(4), folder: true);
        host.Access("FS01", @"D:\Share\Sales", "Permission", "admin", In(5), folder: true);
        host.Access("FS01", @"D:\Share\HR\pay.xlsx", "Read", "mallory", In(5), denied: true);
        host.Access("FS01", @"D:\Share\HR\pay.xlsx", "Write", "mallory", In(5), denied: true);
        // the period before it
        host.Access("FS01", @"D:\Share\Sales\a.xlsx", "Read", "alice", In(-3));
        host.Access("FS01", @"D:\Share\Sales\a.xlsx", "Read", "alice", In(-4));
        host.Access("FS01", @"D:\Share\HR\pay.xlsx", "Read", "mallory", In(-4), denied: true);
        // older, and after the end
        host.Access("FS01", @"D:\Share\Sales\a.xlsx", "Read", "alice", In(-20));
        host.Access("FS01", @"D:\Share\Sales\a.xlsx", "Read", "alice", In(8));
        return host;
    }

    [Fact]
    public async Task Counts_match_the_seeded_records_and_denied_attempts_are_separate()
    {
        using var host = Seeded();
        var data = await host.Builder.BuildDataAsync(ReportTestHost.Weekly(), ReportTestHost.Smtp(), Slot);
        var s = data.Summary;
        Assert.Equal(7, s.Total);   // the two refused attempts are not accesses
        Assert.Equal(2, s.Denied);
        Assert.Equal(2, s.PermissionChanges);
        Assert.Equal(2, s.UniqueFiles);   // folders do not count as files
        Assert.Equal(4, s.ActiveUsers);   // alice, bob, carol, admin (mallory was refused)
        Assert.Equal(new Dictionary<string, int> { ["Read"] = 3, ["Write"] = 1, ["Delete"] = 1, ["Permission"] = 2 }, s.ByType);
        // the previous period, for the comparison
        Assert.Equal((2, 1, 0), (s.PreviousTotal, s.PreviousDenied, s.PreviousPermissionChanges));
        Assert.Equal(["Sales", "HR"], s.Changes.Select(c => c.Path.Split('\\')[^1]));   // newest first
        Assert.Equal("admin", s.Changes[0].User);
    }

    [Fact]
    public async Task Top_lists_are_ordered_and_limited()
    {
        using var host = Seeded();
        var data = await host.Builder.BuildDataAsync(ReportTestHost.Weekly(topN: 1), ReportTestHost.Smtp(), Slot);
        var file = Assert.Single(data.TopFiles);
        Assert.Equal((@"D:\Share\Sales\a.xlsx", 3, 2, 1), (file.Path, file.Total, file.Reads, file.Writes));
        Assert.Contains(Assert.Single(data.TopUsers).User, new[] { "alice", "carol", "admin" });
        Assert.Single(data.TopFolders);

        var all = await host.Builder.BuildDataAsync(ReportTestHost.Weekly(), ReportTestHost.Smtp(), Slot);
        Assert.Equal(4, all.TopUsers.Count);
        Assert.Equal("bob", all.TopUsers[^1].User);
    }

    [Fact]
    public async Task A_period_without_records_is_empty_but_complete()
    {
        using var host = new ReportTestHost();
        var data = await host.Builder.BuildDataAsync(ReportTestHost.Weekly(), ReportTestHost.Smtp(), Slot);
        Assert.Equal((0, 0, 0, 0, 0), (data.Summary.Total, data.Summary.Denied, data.Summary.PermissionChanges, data.Summary.UniqueFiles, data.Summary.ActiveUsers));
        Assert.Empty(data.Summary.ByType);
        Assert.Empty(data.TopFiles);
        Assert.Empty(data.AlertGroups!);
        var (html, text) = ReportHtml.Render(data);
        Assert.Contains("No accesses were recorded in this period.", text);
        Assert.Contains("No alerts were sent in this period.", html);
    }

    [Fact]
    public async Task A_scoped_report_counts_only_the_scope_and_leaves_out_what_cannot_be_limited()
    {
        using var host = Seeded();
        host.Integrity.Summary = new IntegritySummary("ok", Slot, Slot, 0, null, 10, "ab", 0, "FAM-ANCHOR v1 seq=10");
        host.Db(db => db.Agents.Add(new Agent { Id = "a1", Name = "FS01", KeyHash = "x", CreatedAt = Slot.AddDays(-30) }));
        host.Db(db => db.AuditLogs.Add(new AuditLogEntry { Time = In(2), Action = "alert.sent", UserName = "(system)", Detail = "type=Delete, server=FS01, user=carol, count=100, channels=[email=ok]" }));

        var scope = AccessScope.Parse([@"D:\Share\Sales"]);
        var scoped = await host.Builder.BuildDataAsync(ReportTestHost.Weekly(scope: scope), ReportTestHost.Smtp(), Slot);
        Assert.Equal(4, scoped.Summary.Total);   // 3 on a.xlsx + the permission change of Sales
        Assert.Equal(0, scoped.Summary.Denied);
        Assert.Equal(1, scoped.Summary.PermissionChanges);
        Assert.Equal(@"D:\Share\Sales\a.xlsx", Assert.Single(scoped.TopFiles).Path);
        Assert.DoesNotContain(scoped.TopUsers, u => u.User == "carol");
        Assert.Null(scoped.AlertGroups);
        Assert.Null(scoped.Agents);
        Assert.Null(scoped.Integrity);
        var (html, text) = ReportHtml.Render(scoped);
        Assert.DoesNotContain("pay.xlsx", html);
        Assert.DoesNotContain("pay.xlsx", text);
        Assert.DoesNotContain("FAM-ANCHOR", text);
        Assert.Contains("This report covers your folders only.", text);

        // the report for everyone has them all
        var admin = await host.Builder.BuildDataAsync(ReportTestHost.Weekly(), ReportTestHost.Smtp(), Slot);
        Assert.NotNull(admin.AlertGroups);
        Assert.NotNull(admin.Agents);
        Assert.NotNull(admin.Integrity);
        Assert.Equal("FAM-ANCHOR v1 seq=10", admin.Integrity!.AnchorLine);
    }

    [Fact]
    public async Task Integrity_is_left_out_when_tamper_detection_is_off()
    {
        using var host = new ReportTestHost();   // the fake says "disabled"
        Assert.Null((await host.Builder.BuildDataAsync(ReportTestHost.Weekly(), ReportTestHost.Smtp(), Slot)).Integrity);
    }

    [Fact]
    public async Task Alerts_sent_come_from_the_operation_log()
    {
        using var host = new ReportTestHost();
        void Alert(double day, string detail) => host.Db(db => db.AuditLogs.Add(
            new AuditLogEntry { Time = In(day), Action = "alert.sent", UserName = "(system)", Detail = detail }));
        Alert(1, "type=Delete, server=FS01, user=carol, count=120, channels=[email=ok]");
        Alert(2, "type=Delete, server=FS01, user=dave, count=130, channels=[email=ok]");
        Alert(3, "type=Ransomware, rule=extension, server=FS01, user=mallory, count=40, channels=[email=ok, webhook=ok]");
        Alert(4, "type=Denied, server=FS02, user=mallory, count=25, channels=[email=failed]");
        Alert(5, "type=gap, server=FS01, channels=[email=ok]");
        Alert(-3, "type=Delete, server=FS01, user=old, count=1, channels=[]");   // before the period
        host.Db(db => db.AuditLogs.Add(new AuditLogEntry { Time = In(2), Action = "export.csv", UserName = "x", Detail = "type=Delete" }));

        var data = await host.Builder.BuildDataAsync(ReportTestHost.Weekly(), ReportTestHost.Smtp(), Slot);
        Assert.Equal(new[] { "Delete", "Denied", "Ransomware[extension]", "gap" }.Order(), data.AlertGroups!.Select(g => g.Type).Order());
        Assert.Equal(2, data.AlertGroups!.Single(g => g.Type == "Delete").Count);
        // ransomware and refused-access alerts are listed one by one, newest first
        Assert.Equal(["Denied", "Ransomware[extension]"], data.AlertRows.Select(a => a.Type));
        Assert.Equal(("FS02", "mallory", "25"), (data.AlertRows[0].Server, data.AlertRows[0].User, data.AlertRows[0].Count));
    }

    [Fact]
    public void Alert_details_are_parsed_up_to_the_channels()
    {
        var map = ReportBuilder.ParseAlertDetail("type=Ransomware, rule=burst, server=FS01, user=a=b, count=3, channels=[email=ok, x=y]");
        Assert.Equal(("Ransomware", "burst", "FS01", "a=b", "3"), (map["type"], map["rule"], map["server"], map["user"], map["count"]));
        Assert.DoesNotContain("x", map.Keys);
        Assert.Empty(ReportBuilder.ParseAlertDetail(null));
    }

    [Fact]
    public async Task Agents_are_listed_with_their_state()
    {
        using var host = new ReportTestHost();
        host.Db(db =>
        {
            db.Agents.Add(new Agent { Id = "1", Name = "FS01", KeyHash = "x", CreatedAt = Slot.AddDays(-60), LastSeenAt = Slot.AddMinutes(-2), Os = "Windows Server 2022", Version = "9.0.0", AuditPolicyOk = true });
            db.Agents.Add(new Agent { Id = "2", Name = "FS02", KeyHash = "x", CreatedAt = Slot.AddDays(-60), LastSeenAt = Slot.AddHours(-5), Os = "Ubuntu 24.04", Version = "1.0.0", AuditPolicyOk = false, OutboxCount = 3 });
            db.Agents.Add(new Agent { Id = "3", Name = "FS03", KeyHash = "x", CreatedAt = Slot.AddDays(-60), LastSeenAt = Slot.AddDays(-9), Disabled = true });
        });
        var agents = (await host.Builder.BuildDataAsync(ReportTestHost.Weekly(), ReportTestHost.Smtp(), Slot)).Agents!;
        Assert.Equal(["FS01", "FS02", "FS03"], agents.Select(a => a.Name));
        Assert.Equal([false, true, false], agents.Select(a => a.Offline));   // a disabled agent is not "offline"
        Assert.False(agents[0].Outdated);   // 9.0.0 is not older than this build
        Assert.False(agents[1].AuditOk);
        Assert.Equal(3, agents[1].Outbox);
    }

    [Fact]
    public async Task Permissions_come_from_the_stored_scans_and_a_report_never_scans()
    {
        using var host = new ReportTestHost();
        host.Permissions.Reports.Add(new StoredPermissionReport { Server = "FS01", Root = @"D:\Share\Sales", ScannedAt = Slot.AddDays(-2) });
        host.Permissions.Reports.Add(new StoredPermissionReport { Server = "FS01", Root = @"D:\Share\HR", ScannedAt = Slot.AddDays(-40) });
        host.Permissions.Reports.Add(new StoredPermissionReport { Server = "FS02", Root = "/srv/share", ScannedAt = Slot.AddDays(-1) });

        var admin = (await host.Builder.BuildDataAsync(ReportTestHost.Weekly(), ReportTestHost.Smtp(), Slot)).Permissions!;
        Assert.Equal(3, admin.Roots.Count);
        Assert.Equal([true, false, false], admin.Roots.OrderBy(r => r.Server).ThenBy(r => r.Root).Select(r => r.Old));   // HR: older than 14 days
        Assert.Contains(admin.Roots, r => r.Root == @"D:\Share\HR" && r.Old);
        Assert.Contains(admin.Roots, r => r.Root == @"D:\Share\Sales" && !r.Old);

        // a scoped report mentions only the scans of its folders
        var scoped = (await host.Builder.BuildDataAsync(ReportTestHost.Weekly(scope: AccessScope.Parse([@"D:\Share\Sales\Q4"])), ReportTestHost.Smtp(), Slot)).Permissions!;
        Assert.Equal([@"D:\Share\Sales"], scoped.Roots.Select(r => r.Root));
        Assert.Empty(scoped.NeverScanned);
        var folder = (await host.Builder.BuildDataAsync(ReportTestHost.Weekly(scope: AccessScope.Parse([@"FS01|D:\Share"])), ReportTestHost.Smtp(), Slot)).Permissions!;
        Assert.Equal(2, folder.Roots.Count);   // a scope above the scanned folders covers them
        var other = (await host.Builder.BuildDataAsync(ReportTestHost.Weekly(scope: AccessScope.Parse([@"FS09|D:\Nothing"])), ReportTestHost.Smtp(), Slot)).Permissions!;
        Assert.Empty(other.Roots);
    }

    // D:\Share\Docs (Everyone may modify) is in the scan of D:\Share and in its own newer scan: one high row
    [Fact]
    public async Task A_folder_in_two_scans_counts_once()
    {
        using var host = new ReportTestHost();
        StoredPermissionReport Scan(string root, string rel, DateTime at)
        {
            var b = new PermissionResultBuilder("windows", root, new PermissionScanOptions());
            var everyone = b.Principal("Everyone", "S-1-1-0");
            b.AddRow(rel, 1 | 8, -1, [new PermissionAce(everyone, 0, 23, 7)]);
            return new StoredPermissionReport { Server = "FS01", Root = root, Os = "windows", ScannedAt = at, Result = b.Build() };
        }
        host.Permissions.Reports.Add(Scan(@"D:\Share", "Docs", Slot.AddDays(-3)));
        host.Permissions.Reports.Add(Scan(@"D:\Share\Docs", "", Slot.AddDays(-1)));

        var p = (await host.Builder.BuildDataAsync(ReportTestHost.Weekly(), ReportTestHost.Smtp(), Slot)).Permissions!;
        Assert.Equal(1, p.High);
        Assert.Equal([@"D:\Share", @"D:\Share\Docs"], p.Roots.Select(r => r.Root));
        Assert.Equal([0, 1], p.Roots.Select(r => r.High));   // counted with the newer scan
    }

    [Fact]
    public async Task The_mail_has_subject_text_html_and_a_webhook_summary_for_the_full_report_only()
    {
        using var host = Seeded();
        var mail = await host.Builder.BuildMailAsync(ReportTestHost.Weekly(), ReportTestHost.Smtp(), Slot, test: false);
        Assert.Equal($"[FileAccessMonitor] Weekly report 2026-10-26 - 2026-11-02 ({ServerConfigService.LocalName})", mail.Subject);
        Assert.Contains("a.xlsx", mail.Text);
        Assert.Contains("a.xlsx", mail.Html);
        Assert.NotNull(mail.WebhookText);
        Assert.DoesNotContain("a.xlsx", mail.WebhookText);   // numbers only
        Assert.DoesNotContain("alice", mail.WebhookText);

        var test = await host.Builder.BuildMailAsync(ReportTestHost.Weekly(), ReportTestHost.Smtp(), Slot, test: true);
        Assert.StartsWith("[TEST] [FileAccessMonitor]", test.Subject);

        var scoped = await host.Builder.BuildMailAsync(ReportTestHost.Weekly(scope: AccessScope.Parse([@"D:\Share\Sales"])), ReportTestHost.Smtp(), Slot, test: false);
        Assert.Null(scoped.WebhookText);
    }

    [Fact]
    public async Task Csv_attachments_hold_the_period_rows_and_can_be_switched_off()
    {
        using var host = Seeded();
        host.Permissions.Reports.Add(new StoredPermissionReport { Server = "FS01", Root = @"D:\Share", ScannedAt = Slot });
        var with = await host.Builder.BuildMailAsync(ReportTestHost.Weekly(csv: true), ReportTestHost.Smtp(), Slot, test: false);
        Assert.Equal(["denied.csv", "permission-changes.csv", "top-files.csv", "top-users.csv"], with.Attachments.Select(a => a.FileName).Order());
        var denied = System.Text.Encoding.UTF8.GetString(with.Attachments.Single(a => a.FileName == "denied.csv").Content);
        Assert.Equal(3, denied.TrimEnd().Split('\n').Length);   // header + 2 refused attempts
        Assert.Contains("mallory", denied);
        Assert.Equal([0xEF, 0xBB, 0xBF], with.Attachments[0].Content.Take(3).Select(b => (int)b));

        var without = await host.Builder.BuildMailAsync(ReportTestHost.Weekly(csv: false), ReportTestHost.Smtp(), Slot, test: false);
        Assert.Empty(without.Attachments);
    }
}
