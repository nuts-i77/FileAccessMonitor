using FileAccessMonitor.Controllers;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class DeniedAlertTests
{
    private static readonly DateTime T0 = new(2026, 11, 3, 1, 0, 0, DateTimeKind.Utc);

    private static AccessRecord Rec(string user, string type, double minutes, bool denied = false, bool folder = false) => new()
    {
        UserName = user, AccessType = type, AccessTime = T0.AddMinutes(minutes), Denied = denied, IsFolder = folder,
        FolderPath = @"D:\Share\A", FilePath = $@"D:\Share\A\f{minutes}.txt", FileName = $"f{minutes}.txt", ServerName = "FS01",
    };

    private static IEnumerable<AccessRecord> Burst(string user, string type, int count, bool denied = false, bool folder = false) =>
        Enumerable.Range(0, count).Select(i => Rec(user, type, i * 0.05, denied, folder));

    [Fact]
    public void Denied_burst_alerts_per_user_with_its_own_type()
    {
        var d = new AlertDetector(new AlertRules(0, 0, 5, 30, DeniedThreshold: 20));
        var a = Assert.Single(d.Process(Burst("u", "Read", 20, denied: true)));
        Assert.Equal(("Denied", "u", 20, "Normal"), (a.AccessType, a.UserName, a.Count, a.Priority));
        Assert.Equal("", a.Rule);
    }

    [Fact]
    public void Denied_burst_counts_any_type_and_folders()
    {
        var d = new AlertDetector(new AlertRules(0, 0, 5, 30, DeniedThreshold: 6));
        var records = Burst("u", "Read", 2, denied: true).Concat(Burst("u", "Write", 2, denied: true))
            .Concat(Burst("u", "Delete", 1, denied: true)).Concat(Burst("u", "Read", 1, denied: true, folder: true));
        Assert.Single(d.Process(records));
    }

    [Fact]
    public void Below_threshold_off_and_other_users_do_not_alert()
    {
        Assert.Empty(new AlertDetector(new AlertRules(0, 0, 5, 30, DeniedThreshold: 20)).Process(Burst("u", "Read", 19, denied: true)));
        Assert.Empty(new AlertDetector(new AlertRules(0, 0, 5, 30, DeniedThreshold: 0)).Process(Burst("u", "Read", 100, denied: true)));
        var mixed = Burst("a", "Read", 10, denied: true).Concat(Burst("b", "Read", 10, denied: true));
        Assert.Empty(new AlertDetector(new AlertRules(0, 0, 5, 30, DeniedThreshold: 20)).Process(mixed));
    }

    [Fact]
    public void Denied_burst_respects_the_cooldown()
    {
        var d = new AlertDetector(new AlertRules(0, 0, 5, 30, DeniedThreshold: 5));
        Assert.Single(d.Process(Burst("u", "Read", 5, denied: true)));
        Assert.Empty(d.Process(Burst("u", "Read", 5, denied: true)));
    }

    [Fact]
    public void Denied_records_do_not_count_towards_the_thresholds()
    {
        var d = new AlertDetector(new AlertRules(DeleteThreshold: 5, WriteThreshold: 5, WindowMinutes: 5, CooldownMinutes: 30, ReadThreshold: 5));
        Assert.Empty(d.Process(Burst("u", "Delete", 50, denied: true)
            .Concat(Burst("u", "Write", 50, denied: true)).Concat(Burst("u", "Read", 50, denied: true))));
    }

    [Fact]
    public void Create_counts_as_write_and_permission_and_rename_do_not_count()
    {
        var d = new AlertDetector(new AlertRules(DeleteThreshold: 0, WriteThreshold: 5, WindowMinutes: 5, CooldownMinutes: 30));
        var a = Assert.Single(d.Process(Burst("u", "Create", 3).Concat(Burst("u", "Write", 2))));
        Assert.Equal("Write", a.AccessType);
        Assert.Empty(new AlertDetector(new AlertRules(5, 5, 5, 30, 5)).Process(
            Burst("u", "Permission", 50).Concat(Burst("u", "Rename", 50))));
    }

    [Fact]
    public void Denied_text_in_both_languages()
    {
        var a = Assert.Single(new AlertDetector(new AlertRules(0, 0, 5, 30, DeniedThreshold: 3)).Process(Burst("u", "Read", 3, denied: true)));
        Assert.Contains("refused", AlertService.Format(a, "en").Title);
        Assert.Contains("拒否", AlertService.Format(a, "ja").Title);
        Assert.DoesNotContain("[HIGH PRIORITY]", AlertService.Format(a, "en").Title);
    }

    [Fact]
    public void Search_filter_and_denied_query_pick_the_right_records()
    {
        var records = new[] { Rec("u", "Read", 0), Rec("u", "Read", 1, denied: true) }.AsQueryable();
        Assert.Single(StatsController.ApplyDenied(records, "only"), r => r.Denied);
        Assert.Single(StatsController.ApplyDenied(records, "exclude"), r => !r.Denied);
        Assert.Equal(2, StatsController.ApplyDenied(records, null).Count());
        Assert.Equal(2, StatsController.ApplyDenied(records, "").Count());
    }
}
