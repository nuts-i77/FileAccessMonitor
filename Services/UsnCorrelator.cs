using FileAccessMonitor.Models;

namespace FileAccessMonitor.Services;

// Joins the Security log (who, which file) with the NTFS change journal (a file was created, a file
// got a new name). The log has neither: a first write is logged like any other, and a rename only
// shows the DELETE access to the old name. Pure logic; the journal is read by UsnJournalReader and
// time is passed in, so it is testable. Thread safe: the reader adds facts, the collector holds
// and releases records.
public class UsnCorrelator
{
    // A record waits until the journal has been read up to its time (plus slack), at most this long
    public static readonly TimeSpan CatchUpSlack = TimeSpan.FromSeconds(3);
    public static readonly TimeSpan MaxHold = TimeSpan.FromSeconds(10);
    // A write is the first write of a created file if the create is at most this long before it
    // (apps that create a file and write to it later), or up to CreateLag after (clock granularity)
    public static readonly TimeSpan CreateLead = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan CreateLag = TimeSpan.FromSeconds(2);
    // The rename happens after the DELETE access that the record comes from (RenameLead is clock slack)
    public static readonly TimeSpan RenameLead = TimeSpan.FromSeconds(1);
    public static readonly TimeSpan RenameLag = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan FactRetention = TimeSpan.FromMinutes(10);
    public const int MaxFacts = 100_000;

    private sealed record Held(AccessRecord Record, DateTime HeldUtc);

    private readonly object _gate = new();
    private readonly Dictionary<string, List<(DateTime Time, string? NewPath)>> _creates = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<(DateTime Time, string? NewPath)>> _renames = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Held> _held = [];
    private int _factCount;
    private DateTime _lastPrune = DateTime.MinValue;
    private DateTime _caughtUpUtc = DateTime.MinValue;

    // The time up to which the journal has been consumed (for several volumes: the oldest of them)
    public DateTime CaughtUpUtc
    {
        get { lock (_gate) return _caughtUpUtc; }
        set { lock (_gate) _caughtUpUtc = value; }
    }

    public bool HasHeld
    {
        get { lock (_gate) return _held.Count > 0; }
    }

    public int FactCount
    {
        get { lock (_gate) return _factCount; }
    }

    public void AddCreate(string path, DateTime timeUtc) => AddFact(_creates, path, timeUtc, null);

    public void AddRename(string oldPath, string newPath, DateTime timeUtc) => AddFact(_renames, oldPath, timeUtc, newPath);

    private void AddFact(Dictionary<string, List<(DateTime, string?)>> facts, string path, DateTime time, string? newPath)
    {
        lock (_gate)
        {
            if (!facts.TryGetValue(path, out var list)) facts[path] = list = [];
            list.Add((time, newPath));
            _factCount++;
            if (_factCount > MaxFacts) Prune(force: true);
        }
    }

    // Records of these kinds are worth waiting for: a write may be the first one of a new file,
    // a rename gets its new name. Denied, permission and folder-write records never are.
    public static bool NeedsCorrelation(AccessRecord r) =>
        !r.Denied && r.AccessType is AccessTypes.Rename or AccessTypes.Write
        && (r.AccessType == AccessTypes.Rename || !r.IsFolder);

    public void Hold(AccessRecord record, DateTime nowUtc)
    {
        lock (_gate) _held.Add(new Held(record, nowUtc));
    }

    // Records whose facts must have arrived by now, in the order they were held. The first record
    // that is not ready stops the release, so the order of events is kept (every record is ready
    // after MaxHold, so none is stuck). force: shutdown, release everything.
    public List<AccessRecord> Release(DateTime nowUtc, bool force = false)
    {
        lock (_gate)
        {
            var released = new List<AccessRecord>();
            var n = 0;
            while (n < _held.Count)
            {
                var h = _held[n];
                var ready = force || _caughtUpUtc >= h.Record.AccessTime + CatchUpSlack || nowUtc - h.HeldUtc >= MaxHold;
                if (!ready) break;
                Resolve(h.Record);
                released.Add(h.Record);
                n++;
            }
            _held.RemoveRange(0, n);
            if (nowUtc - _lastPrune >= TimeSpan.FromSeconds(30)) { _lastPrune = nowUtc; Prune(force: false); }
            return released;
        }
    }

    private void Resolve(AccessRecord r)
    {
        var t = r.AccessTime;
        if (r.AccessType == AccessTypes.Write)
        {
            // Consumed, so a later write to the same file stays a write
            if (TakeNearest(_creates, r.FilePath, t - CreateLead, t + CreateLag, t) != null)
                r.AccessType = AccessTypes.Create;
        }
        else if (r.AccessType == AccessTypes.Rename)
        {
            if (TakeNearest(_renames, r.FilePath, t - RenameLead, t + RenameLag, t) is { } fact)
                r.NewPath = fact.NewPath;
        }
    }

    private (DateTime Time, string? NewPath)? TakeNearest(
        Dictionary<string, List<(DateTime Time, string? NewPath)>> facts, string path, DateTime from, DateTime to, DateTime near)
    {
        if (!facts.TryGetValue(path, out var list)) return null;
        var best = -1;
        for (var i = 0; i < list.Count; i++)
        {
            if (list[i].Time < from || list[i].Time > to) continue;
            if (best < 0 || (list[i].Time - near).Duration() < (list[best].Time - near).Duration()) best = i;
        }
        if (best < 0) return null;
        var fact = list[best];
        list.RemoveAt(best);
        _factCount--;
        if (list.Count == 0) facts.Remove(path);
        return fact;
    }

    // Facts older than FactRetention behind the journal position cannot match any record any more;
    // above MaxFacts the oldest half goes regardless.
    private void Prune(bool force)
    {
        if (!force && _factCount < 1000) return;
        var limit = _caughtUpUtc > DateTime.MinValue + FactRetention ? _caughtUpUtc - FactRetention : DateTime.MinValue;
        if (force && _factCount > MaxFacts)
        {
            var all = _creates.Values.Concat(_renames.Values).SelectMany(l => l).Select(f => f.Time).Order().ToList();
            limit = all[all.Count / 2];
        }
        Prune(_creates, limit);
        Prune(_renames, limit);
    }

    private void Prune(Dictionary<string, List<(DateTime Time, string? NewPath)>> facts, DateTime limit)
    {
        foreach (var path in facts.Keys.ToList())
        {
            var list = facts[path];
            _factCount -= list.RemoveAll(f => f.Time < limit);
            if (list.Count == 0) facts.Remove(path);
        }
    }
}
