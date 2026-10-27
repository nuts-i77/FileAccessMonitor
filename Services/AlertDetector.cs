using FileAccessMonitor.Models;

namespace FileAccessMonitor.Services;

public record AlertRules(int DeleteThreshold, int WriteThreshold, int WindowMinutes, int CooldownMinutes);

public record Alert(
    string AccessType, string UserName, int Count, int WindowMinutes,
    DateTime FromUtc, DateTime ToUtc, string? ClientIp, string? ClientMachine,
    IReadOnlyList<(string Folder, int Count)> TopFolders, IReadOnlyList<string> SamplePaths);

// Detects bursts: one user deleting (or writing) at least N files within M minutes.
// Uses the event time, so a backlog read after a restart is judged by when it happened.
// Not thread-safe; called only from the collector's single consumer.
public class AlertDetector(AlertRules rules)
{
    private readonly Dictionary<(string User, string Type), Queue<AccessRecord>> _windows = new();
    private readonly Dictionary<(string User, string Type), DateTime> _lastAlert = new();

    public AlertRules Rules { get; } = rules;

    public List<Alert> Process(IEnumerable<AccessRecord> records)
    {
        var alerts = new List<Alert>();
        foreach (var r in records)
        {
            var threshold = r.AccessType switch
            {
                "Delete" => Rules.DeleteThreshold,
                "Write" => Rules.WriteThreshold,
                _ => 0,
            };
            if (threshold <= 0) continue;

            var key = (r.UserName, r.AccessType);
            if (!_windows.TryGetValue(key, out var window))
                _windows[key] = window = new Queue<AccessRecord>();

            window.Enqueue(r);
            var windowStart = r.AccessTime.AddMinutes(-Rules.WindowMinutes);
            while (window.Count > 0 && (window.Peek().AccessTime < windowStart || window.Count > threshold))
                window.Dequeue();

            if (window.Count < threshold) continue;
            if (_lastAlert.TryGetValue(key, out var last) && r.AccessTime < last.AddMinutes(Rules.CooldownMinutes))
                continue;

            _lastAlert[key] = r.AccessTime;
            alerts.Add(BuildAlert(window.ToList()));
            window.Clear();
        }
        return alerts;
    }

    private Alert BuildAlert(List<AccessRecord> items)
    {
        var first = items[0];
        var latest = items[^1];
        var topFolders = items
            .GroupBy(i => i.FolderPath, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .Take(3)
            .Select(g => (g.Key, g.Count()))
            .ToList();
        var samples = items.Select(i => i.FilePath).Distinct(StringComparer.OrdinalIgnoreCase).Take(5).ToList();

        return new Alert(first.AccessType, first.UserName, items.Count, Rules.WindowMinutes,
            first.AccessTime, latest.AccessTime, latest.ClientIp, latest.ClientMachine, topFolders, samples);
    }
}
