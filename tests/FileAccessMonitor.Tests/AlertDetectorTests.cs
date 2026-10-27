using FileAccessMonitor.Models;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class AlertDetectorTests
{
    private static readonly DateTime T0 = new(2026, 10, 27, 1, 0, 0, DateTimeKind.Utc);

    private static AccessRecord Rec(string user, string type, double minutes, string folder = @"D:\Share\A") => new()
    {
        UserName = user, AccessType = type, AccessTime = T0.AddMinutes(minutes),
        FolderPath = folder, FilePath = $@"{folder}\f{minutes}.txt", FileName = $"f{minutes}.txt",
    };

    private static IEnumerable<AccessRecord> Burst(string user, string type, int count, double start = 0, double step = 0.1) =>
        Enumerable.Range(0, count).Select(i => Rec(user, type, start + i * step));

    [Fact]
    public void Alerts_when_threshold_reached_within_window()
    {
        var d = new AlertDetector(new AlertRules(DeleteThreshold: 10, WriteThreshold: 0, WindowMinutes: 5, CooldownMinutes: 30));
        var alerts = d.Process(Burst(@"CORP\sato", "Delete", 10));

        var a = Assert.Single(alerts);
        Assert.Equal(@"CORP\sato", a.UserName);
        Assert.Equal(10, a.Count);
        Assert.Equal(@"D:\Share\A", a.TopFolders[0].Folder);
        Assert.Equal(5, a.SamplePaths.Count);
    }

    [Fact]
    public void Does_not_alert_below_threshold_or_outside_window()
    {
        var d = new AlertDetector(new AlertRules(10, 0, 5, 30));
        Assert.Empty(d.Process(Burst(@"CORP\sato", "Delete", 9)));
        // 10 deletes spread over 9 minutes never has 10 inside a 5-minute window
        var d2 = new AlertDetector(new AlertRules(10, 0, 5, 30));
        Assert.Empty(d2.Process(Burst(@"CORP\sato", "Delete", 10, step: 1)));
    }

    [Fact]
    public void Counts_users_and_types_separately_and_ignores_disabled_types()
    {
        var d = new AlertDetector(new AlertRules(DeleteThreshold: 5, WriteThreshold: 0, WindowMinutes: 5, CooldownMinutes: 30));
        var records = Burst("a", "Delete", 3).Concat(Burst("b", "Delete", 3)).Concat(Burst("a", "Write", 50)).Concat(Burst("a", "Read", 50));
        Assert.Empty(d.Process(records));
    }

    [Fact]
    public void Respects_cooldown()
    {
        var d = new AlertDetector(new AlertRules(5, 0, 5, CooldownMinutes: 30));
        Assert.Single(d.Process(Burst("a", "Delete", 5, start: 0)));
        Assert.Empty(d.Process(Burst("a", "Delete", 5, start: 10)));   // within 30 min
        Assert.Single(d.Process(Burst("a", "Delete", 5, start: 40)));   // after cooldown
    }

    [Fact]
    public void Alert_text_contains_the_essentials()
    {
        var d = new AlertDetector(new AlertRules(3, 0, 5, 30));
        var alert = Assert.Single(d.Process(Burst(@"CORP\sato", "Delete", 3)));
        var (title, body) = AlertService.Format(alert, "en");
        Assert.Contains("Mass deletion", title);
        Assert.Contains(@"CORP\sato", body);
        Assert.Contains("3 within 5 minutes", body);
    }
}
