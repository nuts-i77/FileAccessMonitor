using FileAccessMonitor.Models;

namespace FileAccessMonitor.Services;

// Merges repeated records of the same user, path and type that follow each other within a window
// (sliding: every repeat extends it), so that a client retrying a refused access, or one command
// that makes several permission calls, produces one record. Used for denied accesses (60 seconds)
// and for permission changes (3 seconds) by the Linux collector.
public class DeniedMerger
{
    public static readonly TimeSpan DeniedWindow = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan PermissionWindow = TimeSpan.FromSeconds(3);
    private const int MaxEntries = 20_000;

    private readonly TimeSpan _window;
    private readonly Dictionary<(string User, string Path, string Type), DateTime> _last = new();
    private DateTime _newest = DateTime.MinValue;

    public DeniedMerger(TimeSpan window) => _window = window;

    public bool ShouldRecord(AccessRecord record)
    {
        if (_window <= TimeSpan.Zero) return true;
        var key = (record.UserName.ToUpperInvariant(), record.FilePath, record.AccessType);
        var time = record.AccessTime;
        var merged = _last.TryGetValue(key, out var last) && (time - last).Duration() < _window;
        _last[key] = merged && last > time ? last : time;

        if (time > _newest) _newest = time;
        if (_last.Count > MaxEntries) Prune();
        return !merged;
    }

    private void Prune()
    {
        foreach (var key in _last.Where(kv => _newest - kv.Value >= _window).Select(kv => kv.Key).ToList())
            _last.Remove(key);
        if (_last.Count > MaxEntries) _last.Clear(); // everything is recent: forget rather than grow
    }
}
