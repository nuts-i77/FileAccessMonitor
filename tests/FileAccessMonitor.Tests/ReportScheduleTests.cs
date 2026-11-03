using System.Text.Json.Nodes;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

// Slots, catch-up, skipping, retries: with a fake clock, no waiting and no SMTP
public class ReportScheduleTests
{
    private static readonly TimeZoneInfo Utc = TimeZoneInfo.Utc;
    private static DateTime U(int y, int mo, int d, int h = 0, int mi = 0) => new(y, mo, d, h, mi, 0, DateTimeKind.Utc);
    private static DateTime L(int y, int mo, int d, int h = 0, int mi = 0) => new(y, mo, d, h, mi, 0, DateTimeKind.Unspecified);

    private static ReportSettings Weekly(int dow = 1, string time = "09:00") =>
        new() { Enabled = true, Frequency = "weekly", DayOfWeek = dow, Time = time };
    private static ReportSettings Daily(string time = "09:00") => new() { Enabled = true, Frequency = "daily", Time = time };
    private static ReportSettings Monthly(int dom, string time = "09:00") =>
        new() { Enabled = true, Frequency = "monthly", DayOfMonth = dom, Time = time };

    private static TimeZoneInfo NewYork()
    {
        try { return TimeZoneInfo.FindSystemTimeZoneById("America/New_York"); }
        catch (TimeZoneNotFoundException) { return TimeZoneInfo.FindSystemTimeZoneById("Eastern Standard Time"); }
    }

    // ---- slots

    [Theory]
    [InlineData(2026, 11, 4, 10, 0, 2026, 11, 2)]   // Wednesday: the Monday before
    [InlineData(2026, 11, 2, 9, 0, 2026, 11, 2)]    // exactly at the slot
    [InlineData(2026, 11, 2, 8, 59, 2026, 10, 26)]  // a minute before it
    [InlineData(2026, 11, 8, 23, 59, 2026, 11, 2)]
    public void Weekly_latest_slot(int y, int mo, int d, int h, int mi, int ey, int emo, int ed) =>
        Assert.Equal(L(ey, emo, ed, 9), ReportSchedule.LatestSlotAtOrBefore(Weekly(), U(y, mo, d, h, mi), Utc));

    [Fact]
    public void Weekly_next_slot_is_a_week_after_the_latest()
    {
        Assert.Equal(L(2026, 11, 9, 9), ReportSchedule.NextSlot(Weekly(), U(2026, 11, 4, 10), Utc));
        Assert.Equal(L(2026, 11, 9, 9), ReportSchedule.NextSlot(Weekly(), U(2026, 11, 2, 9), Utc));
        Assert.Equal(L(2026, 11, 2, 9), ReportSchedule.NextSlot(Weekly(), U(2026, 11, 2, 8), Utc));
        Assert.Equal(L(2026, 11, 8, 18, 30), ReportSchedule.NextSlot(Weekly(0, "18:30"), U(2026, 11, 2, 8), Utc));   // Sunday
    }

    [Fact]
    public void Daily_slots()
    {
        Assert.Equal(L(2026, 11, 3, 9), ReportSchedule.LatestSlotAtOrBefore(Daily(), U(2026, 11, 3, 9), Utc));
        Assert.Equal(L(2026, 11, 2, 9), ReportSchedule.LatestSlotAtOrBefore(Daily(), U(2026, 11, 3, 8, 59), Utc));
        Assert.Equal(L(2026, 11, 4, 9), ReportSchedule.NextSlot(Daily(), U(2026, 11, 3, 9, 1), Utc));
        Assert.Equal(L(2026, 11, 3, 9), ReportSchedule.NextSlot(Daily(), U(2026, 11, 3, 8), Utc));
    }

    [Fact]
    public void Monthly_slots_across_the_year_end_and_short_months()
    {
        Assert.Equal(L(2026, 10, 15, 9), ReportSchedule.LatestSlotAtOrBefore(Monthly(15), U(2026, 11, 14, 12), Utc));
        Assert.Equal(L(2026, 11, 15, 9), ReportSchedule.LatestSlotAtOrBefore(Monthly(15), U(2026, 11, 15, 9), Utc));
        Assert.Equal(L(2026, 12, 15, 9), ReportSchedule.NextSlot(Monthly(15), U(2026, 11, 20), Utc));
        Assert.Equal(L(2026, 12, 15, 9), ReportSchedule.LatestSlotAtOrBefore(Monthly(15), U(2027, 1, 3), Utc));
        Assert.Equal(L(2027, 1, 15, 9), ReportSchedule.NextSlot(Monthly(15), U(2027, 1, 3), Utc));
        // the 28th exists in every month, February too
        Assert.Equal(L(2027, 2, 28, 9), ReportSchedule.NextSlot(Monthly(28), U(2027, 2, 1), Utc));
        Assert.Equal(L(2027, 2, 28, 9), ReportSchedule.LatestSlotAtOrBefore(Monthly(28), U(2027, 3, 2), Utc));
    }

    [Fact]
    public void The_period_ends_at_the_slot_and_the_previous_one_has_the_same_length()
    {
        var slot = L(2026, 11, 2, 9);
        Assert.Equal((L(2026, 10, 26, 9), slot), ReportSchedule.Period(Weekly(), slot));
        Assert.Equal((L(2026, 11, 1, 9), slot), ReportSchedule.Period(Daily(), slot));
        Assert.Equal((L(2026, 10, 2, 9), slot), ReportSchedule.Period(Monthly(2), slot));
        Assert.Equal(L(2026, 10, 19, 9), ReportSchedule.PreviousFrom(Weekly(), L(2026, 10, 26, 9)));
        Assert.Equal(L(2026, 9, 2, 9), ReportSchedule.PreviousFrom(Monthly(2), L(2026, 10, 2, 9)));
    }

    [Fact]
    public void A_time_that_does_not_exist_moves_forward_by_the_gap()
    {
        var ny = NewYork();
        // 2026-03-08 02:00 -> 03:00 (spring forward): 02:30 does not exist that day
        var slot = ReportSchedule.LatestSlotAtOrBefore(Daily("02:30"), U(2026, 3, 8, 7, 45), ny);   // 03:45 EDT
        Assert.Equal(L(2026, 3, 8, 3, 30), slot);
        Assert.Equal(U(2026, 3, 8, 7, 30), ReportSchedule.ToUtc(slot, ny));
        // 03:15 EDT is before the moved slot: the previous day's slot is still the latest
        Assert.Equal(L(2026, 3, 7, 2, 30), ReportSchedule.LatestSlotAtOrBefore(Daily("02:30"), U(2026, 3, 8, 7, 15), ny));
        Assert.Equal(L(2026, 3, 8, 3, 30), ReportSchedule.NextSlot(Daily("02:30"), U(2026, 3, 8, 7, 15), ny));
        // the next day is normal again
        Assert.Equal(L(2026, 3, 9, 2, 30), ReportSchedule.NextSlot(Daily("02:30"), U(2026, 3, 8, 7, 45), ny));
    }

    [Fact]
    public void A_time_that_happens_twice_counts_at_its_first_occurrence()
    {
        var ny = NewYork();
        // 2026-11-01 02:00 EDT -> 01:00 EST (fall back): 01:30 happens twice
        Assert.Equal(U(2026, 11, 1, 5, 30), ReportSchedule.ToUtc(L(2026, 11, 1, 1, 30), ny));   // 01:30 EDT
        var second = U(2026, 11, 1, 6, 45);                                                      // 01:45 EST, the second pass
        Assert.Equal(L(2026, 11, 1, 1, 30), ReportSchedule.LatestSlotAtOrBefore(Daily("01:30"), second, ny));
        Assert.Equal(L(2026, 11, 2, 1, 30), ReportSchedule.NextSlot(Daily("01:30"), second, ny));

        // and the decision does not send it a second time
        var s = Daily("01:30");
        var state = new ReportState(L(2026, 11, 1, 1, 30), null, 0, null);
        Assert.Equal(ReportAction.None, ScheduledReportService.Decide(s, second, ny, state).Action);
    }

    [Fact]
    public void Catch_up_windows()
    {
        Assert.Equal(TimeSpan.FromHours(6), ReportSchedule.CatchUpWindow("daily"));
        Assert.Equal(TimeSpan.FromHours(24), ReportSchedule.CatchUpWindow("weekly"));
        Assert.Equal(TimeSpan.FromHours(48), ReportSchedule.CatchUpWindow("monthly"));
    }

    // ---- settings

    [Fact]
    public void The_report_is_off_by_default_and_settings_validate()
    {
        Assert.False(new ReportSettings().Enabled);
        Assert.False(ReportSettings.Load(new JsonObject()).Enabled);
        Assert.Null(new ReportSettings().Validate());
        Assert.Equal("report.invalidFrequency", new ReportSettings { Frequency = "hourly" }.Validate());
        Assert.Equal("report.invalidDay", new ReportSettings { DayOfMonth = 29 }.Validate());
        Assert.Equal("report.invalidDay", new ReportSettings { DayOfWeek = 7 }.Validate());
        Assert.Equal("report.invalidTime", new ReportSettings { Time = "9:00am" }.Validate());
        Assert.Equal("report.invalidTime", new ReportSettings { Time = "24:00" }.Validate());
        Assert.Equal("report.invalidTopN", new ReportSettings { TopN = 0 }.Validate());
        Assert.True(new ReportSettings().SameSchedule(new ReportSettings { Csv = false, TopN = 3 }));
        Assert.False(new ReportSettings().SameSchedule(new ReportSettings { Time = "10:00" }));
    }

    [Fact]
    public void Settings_are_read_from_the_Reports_key()
    {
        var root = JsonNode.Parse("""{ "Reports": { "Enabled": true, "Frequency": "monthly", "DayOfMonth": 5, "Time": "07:30", "Csv": false } }""")!.AsObject();
        var s = ReportSettings.Load(root);
        Assert.Equal((true, "monthly", 5, "07:30", false, true), (s.Enabled, s.Frequency, s.DayOfMonth, s.Time, s.Csv, s.ScopedViewers));
    }

    // ---- decisions

    [Fact]
    public void Decide_covers_every_case()
    {
        var s = Weekly();
        var slot = L(2026, 11, 2, 9);
        var before = new ReportState(L(2026, 10, 26, 9), null, 0, null);
        ReportAction Do(ReportSettings st, DateTime now, ReportState state) => ScheduledReportService.Decide(st, now, Utc, state).Action;

        Assert.Equal(ReportAction.None, Do(Weekly().with0(false), U(2026, 11, 2, 10), before));            // off
        Assert.Equal(ReportAction.None, Do(s, U(2026, 11, 2, 8, 59), before));                              // not yet
        Assert.Equal(ReportAction.Send, Do(s, U(2026, 11, 2, 9), before));
        Assert.Equal(ReportAction.Send, Do(s, U(2026, 11, 3, 8, 59), before));                              // within 24 h
        Assert.Equal(ReportAction.SkipMissed, Do(s, U(2026, 11, 3, 9, 1), before));                         // too late
        Assert.Equal(ReportAction.None, Do(s, U(2026, 11, 2, 12), new ReportState(slot, null, 0, null)));   // handled
        Assert.Equal(ReportAction.Init, Do(s, U(2026, 11, 2, 12), new ReportState(null, null, 0, null)));   // never recorded

        // retries: 15 minutes apart, at most 4 tries
        var now = U(2026, 11, 2, 9, 30);
        Assert.Equal(ReportAction.None, Do(s, now, new ReportState(before.LastSlot, slot, 1, now.AddMinutes(-14))));
        Assert.Equal(ReportAction.Send, Do(s, now, new ReportState(before.LastSlot, slot, 1, now.AddMinutes(-15))));
        Assert.Equal(ReportAction.Send, Do(s, now, new ReportState(before.LastSlot, slot, 3, now.AddMinutes(-20))));
        Assert.Equal(ReportAction.SkipFailed, Do(s, now, new ReportState(before.LastSlot, slot, 4, now.AddMinutes(-20))));
        // attempts of an older slot do not count
        Assert.Equal(ReportAction.Send, Do(s, now, new ReportState(before.LastSlot, L(2026, 10, 26, 9), 4, now.AddMinutes(-20))));
    }

    // ---- the service with a fake clock

    private sealed class Rig : IDisposable
    {
        public readonly ReportTestHost Host;
        public readonly FakeMailer Mailer;
        public readonly FakeClock Clock;
        public ReportSettings Settings = ReportTestHost.Settings();
        public AlertSettings Alerts = ReportTestHost.Smtp();
        public ScheduledReportService Service;

        public Rig(DateTime now, ReportTestHost? host = null, FakeMailer? mailer = null)
        {
            Host = host ?? new ReportTestHost();
            Mailer = mailer ?? new FakeMailer();
            Clock = new FakeClock(now);
            Service = NewService();
        }

        // a restart: a new service object over the same database and clock
        public ScheduledReportService NewService() => Service = new ScheduledReportService(Host.Scopes, Host.Builder, Host.Audit,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ScheduledReportService>.Instance, null, Mailer, Clock, Utc,
            () => Settings, () => Alerts);

        public Task Tick() => Service.TickAsync(CancellationToken.None);
        public List<string> AuditActions() => Host.Query(db => db.AuditLogs.OrderBy(a => a.Id).Select(a => a.Action + ": " + a.Detail).ToList());
        public void Dispose() => Host.Dispose();
    }

    [Fact]
    public async Task Sends_at_the_slot_once_and_not_again_after_a_restart()
    {
        using var rig = new Rig(U(2026, 11, 2, 8));
        await rig.Service.ResetSlotAsync(rig.Settings);   // switched on: the first report is the next slot
        await rig.Tick();
        Assert.Empty(rig.Mailer.Sent);

        rig.Clock.Set(U(2026, 11, 2, 9, 1));
        await rig.Tick();
        var (to, mail) = Assert.Single(rig.Mailer.Sent);
        Assert.Equal("ops@example.com", to);
        Assert.Contains("Weekly report 2026-10-26 - 2026-11-02", mail.Subject);
        Assert.StartsWith("[FileAccessMonitor]", mail.Subject);
        Assert.Contains(rig.AuditActions(), a => a.StartsWith("report.sent: recipients=1, scoped=0, failed=0"));
        var info = await rig.Service.InfoAsync(rig.Settings);
        Assert.Equal(L(2026, 11, 2, 9), info.LastSlot);
        Assert.NotNull(info.LastSent);
        Assert.Equal(L(2026, 11, 9, 9), info.NextSlot);

        rig.Clock.Advance(TimeSpan.FromMinutes(1));
        await rig.Tick();
        rig.NewService();   // restart
        rig.Clock.Advance(TimeSpan.FromHours(3));
        await rig.Tick();
        Assert.Single(rig.Mailer.Sent);
    }

    [Fact]
    public async Task Catches_up_within_the_window_but_skips_an_old_slot()
    {
        using var rig = new Rig(U(2026, 11, 1));
        await rig.Service.ResetSlotAsync(rig.Settings);
        rig.Clock.Set(U(2026, 11, 2, 14));   // the service was down at 09:00, back 5 hours later
        await rig.Tick();
        Assert.Single(rig.Mailer.Sent);

        // down for days: nothing stale is sent, and nothing is sent later for it either
        using var late = new Rig(U(2026, 11, 1));
        await late.Service.ResetSlotAsync(late.Settings);
        late.Clock.Set(U(2026, 11, 4, 10));
        await late.Tick();
        Assert.Empty(late.Mailer.Sent);
        Assert.Contains(late.AuditActions(), a => a.StartsWith("report.skipped: reason=missed, slot=2026-11-02T09:00:00"));
        late.Clock.Set(U(2026, 11, 5));
        await late.Tick();
        Assert.Empty(late.Mailer.Sent);
        Assert.Equal(L(2026, 11, 2, 9), (await late.Service.InfoAsync(late.Settings)).LastSlot);
    }

    [Fact]
    public async Task Turning_the_report_on_after_a_slot_sends_nothing_immediately()
    {
        using var rig = new Rig(U(2026, 11, 3, 10));
        await rig.Service.ResetSlotAsync(rig.Settings);
        await rig.Tick();
        Assert.Empty(rig.Mailer.Sent);
        Assert.Equal(L(2026, 11, 2, 9), (await rig.Service.InfoAsync(rig.Settings)).LastSlot);

        // a report that is off sends nothing even when a slot passes
        using var off = new Rig(U(2026, 11, 1)) { Settings = ReportTestHost.Settings(enabled: false) };
        await off.Tick();
        off.Clock.Set(U(2026, 11, 2, 10));
        await off.Tick();
        Assert.Empty(off.Mailer.Sent);
    }

    [Fact]
    public async Task A_failed_send_is_retried_every_15_minutes_three_times_then_skipped()
    {
        using var rig = new Rig(U(2026, 11, 1));
        await rig.Service.ResetSlotAsync(rig.Settings);
        rig.Mailer.FailFor = _ => new InvalidOperationException("smtp down");
        rig.Clock.Set(U(2026, 11, 2, 9, 1));
        await rig.Tick();
        Assert.Equal(1, rig.Mailer.Attempts);

        rig.Clock.Advance(TimeSpan.FromMinutes(5));
        await rig.Tick();
        Assert.Equal(1, rig.Mailer.Attempts);        // too soon

        for (var expected = 2; expected <= 4; expected++)
        {
            rig.Clock.Advance(TimeSpan.FromMinutes(15));
            await rig.Tick();
            Assert.Equal(expected, rig.Mailer.Attempts);
        }
        Assert.Contains(rig.AuditActions(), a => a.StartsWith("report.skipped: reason=failed") && a.Contains("smtp down"));
        Assert.DoesNotContain(rig.AuditActions(), a => a.StartsWith("report.sent"));

        rig.Clock.Advance(TimeSpan.FromHours(1));
        await rig.Tick();
        Assert.Equal(4, rig.Mailer.Attempts);        // handled: no more tries
        Assert.Equal(L(2026, 11, 2, 9), (await rig.Service.InfoAsync(rig.Settings)).LastSlot);
    }

    [Fact]
    public async Task A_retry_that_works_sends_once_and_resets_the_counter()
    {
        using var rig = new Rig(U(2026, 11, 1));
        await rig.Service.ResetSlotAsync(rig.Settings);
        var failures = 1;
        rig.Mailer.FailFor = _ => failures-- > 0 ? new InvalidOperationException("busy") : null;
        rig.Clock.Set(U(2026, 11, 2, 9, 1));
        await rig.Tick();
        Assert.Empty(rig.Mailer.Sent);

        rig.Clock.Advance(TimeSpan.FromMinutes(15));
        await rig.Tick();
        Assert.Single(rig.Mailer.Sent);
        Assert.Contains(rig.AuditActions(), a => a.StartsWith("report.sent"));
        rig.Clock.Advance(TimeSpan.FromMinutes(30));
        await rig.Tick();
        Assert.Single(rig.Mailer.Sent);
    }

    [Fact]
    public async Task Scoped_viewers_get_their_own_mail_only_when_they_should()
    {
        using var rig = new Rig(U(2026, 11, 1));
        rig.Settings.ScopedViewers = true;
        rig.Host.Viewer("v1", "alice", @"D:\Share\Sales", "alice@example.com");
        rig.Host.Viewer("v2", "bob", @"D:\Share\HR", "bob@example.com", sendReport: false);       // opted out
        rig.Host.Viewer("v3", "carol", @"D:\Share\Ops", "OPS@example.com");                          // already gets the main report
        rig.Host.Viewer("v4", "dave", @"D:\Share\Ops", null);                                        // no address
        rig.Host.Viewer("v5", "erin", "", "erin@example.com");                                       // no folders: not a scoped viewer
        rig.Host.Access("FS01", @"D:\Share\Sales\a.txt", "Read", "alice", U(2026, 10, 30));
        rig.Host.Access("FS01", @"D:\Share\HR\secret.txt", "Read", "bob", U(2026, 10, 30));
        await rig.Service.ResetSlotAsync(rig.Settings);

        rig.Clock.Set(U(2026, 11, 2, 9, 5));
        await rig.Tick();
        Assert.Equal(["ops@example.com", "alice@example.com"], rig.Mailer.Sent.Select(s => s.To));
        var scoped = rig.Mailer.Sent[1].Mail;
        Assert.Contains(@"D:\Share\Sales\a.txt", scoped.Text);
        Assert.DoesNotContain("secret.txt", scoped.Text);
        Assert.DoesNotContain("secret.txt", scoped.Html);
        Assert.Contains("secret.txt", rig.Mailer.Sent[0].Mail.Text);
        Assert.Contains(rig.AuditActions(), a => a.StartsWith("report.sent: recipients=1, scoped=1, failed=0"));
    }

    [Fact]
    public async Task One_failing_viewer_does_not_stop_the_others_or_the_slot()
    {
        using var rig = new Rig(U(2026, 11, 1));
        rig.Settings.ScopedViewers = true;
        rig.Host.Viewer("v1", "alice", @"D:\Share\Sales", "alice@example.com");
        rig.Host.Viewer("v2", "bob", @"D:\Share\HR", "bob@example.com");
        rig.Mailer.FailFor = to => to == "alice@example.com" ? new InvalidOperationException("mailbox full") : null;
        await rig.Service.ResetSlotAsync(rig.Settings);

        rig.Clock.Set(U(2026, 11, 2, 9, 5));
        await rig.Tick();
        Assert.Equal(["ops@example.com", "bob@example.com"], rig.Mailer.Sent.Select(s => s.To));
        Assert.Contains(rig.AuditActions(), a => a.StartsWith("report.sent: recipients=1, scoped=1, failed=1") && a.Contains("mailbox full"));
        Assert.Equal(L(2026, 11, 2, 9), (await rig.Service.InfoAsync(rig.Settings)).LastSlot);
    }

    [Fact]
    public async Task A_test_report_goes_to_the_main_recipients_and_leaves_the_schedule_alone()
    {
        using var rig = new Rig(U(2026, 11, 4, 12));
        rig.Settings.ScopedViewers = true;
        rig.Alerts.WebhookUrl = "https://hooks.example.invalid/x";
        rig.Settings.Webhook = true;
        rig.Host.Viewer("v1", "alice", @"D:\Share\Sales", "alice@example.com");
        await rig.Service.ResetSlotAsync(rig.Settings);
        var before = await rig.Service.InfoAsync(rig.Settings);

        var result = await rig.Service.SendTestAsync(null, null, CancellationToken.None);
        Assert.Equal("ok", result.Status);
        var (to, mail) = Assert.Single(rig.Mailer.Sent);   // never to the scoped viewer
        Assert.Equal("ops@example.com", to);
        Assert.StartsWith("[TEST] [FileAccessMonitor]", mail.Subject);
        Assert.Single(rig.Mailer.Webhooks);
        Assert.Equal(before.LastSlot, (await rig.Service.InfoAsync(rig.Settings)).LastSlot);
    }

    [Fact]
    public async Task A_viewers_report_can_be_previewed_by_mailing_it_to_the_admin()
    {
        using var rig = new Rig(U(2026, 11, 4, 12));
        rig.Host.Viewer("v1", "alice", @"D:\Share\Sales", "alice@example.com");
        rig.Host.Access("FS01", @"D:\Share\HR\secret.txt", "Read", "bob", U(2026, 10, 30));

        var ok = await rig.Service.SendTestAsync("Alice", "admin@example.com", CancellationToken.None);
        Assert.Equal("ok", ok.Status);
        var (to, mail) = Assert.Single(rig.Mailer.Sent);
        Assert.Equal("admin@example.com", to);
        Assert.DoesNotContain("secret.txt", mail.Text);

        Assert.Equal("noViewer", (await rig.Service.SendTestAsync("nobody", "admin@example.com", CancellationToken.None)).Status);
        Assert.Equal("noRecipient", (await rig.Service.SendTestAsync("alice", null, CancellationToken.None)).Status);
    }

    [Fact]
    public async Task Only_one_send_runs_at_a_time()
    {
        using var rig = new Rig(U(2026, 11, 4, 12));
        rig.Mailer.Gate = new TaskCompletionSource();
        var first = rig.Service.SendTestAsync(null, null, CancellationToken.None);
        while (rig.Mailer.Attempts == 0) await Task.Delay(10);

        Assert.Equal("busy", (await rig.Service.SendTestAsync(null, null, CancellationToken.None)).Status);
        rig.Mailer.Gate.SetResult();
        Assert.Equal("ok", (await first).Status);
    }

    [Fact]
    public async Task Without_mail_settings_nothing_is_sent_and_the_slot_is_retried()
    {
        using var rig = new Rig(U(2026, 11, 1));
        rig.Alerts = new AlertSettings { Language = "en" };   // no SMTP host, no recipients
        await rig.Service.ResetSlotAsync(rig.Settings);
        rig.Clock.Set(U(2026, 11, 2, 9, 1));
        await rig.Tick();
        Assert.Empty(rig.Mailer.Sent);
        Assert.Equal(L(2026, 10, 26, 9), (await rig.Service.InfoAsync(rig.Settings)).LastSlot);
    }
}

internal static class ReportSettingsExtensions
{
    // test sugar: a copy with Enabled set
    public static ReportSettings with0(this ReportSettings s, bool enabled)
    {
        var copy = s.Clone();
        copy.Enabled = enabled;
        return copy;
    }
}
