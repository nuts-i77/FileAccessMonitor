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

    // A create or truncation that no write explains is recorded on its own (an empty file, a file opened
    // to be overwritten and left empty: Windows logs no access for them, as no data is written), once the
    // Security log and the journal are this far past it
    public static readonly TimeSpan OpenMatch = TimeSpan.FromSeconds(2);
    public const string UnknownUser = "(unknown)";

    private sealed record Held(AccessRecord Record, DateTime HeldUtc);

    private readonly object _gate = new();
    private readonly Dictionary<string, List<(DateTime Time, string? NewPath)>> _creates = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<(DateTime Time, string? NewPath)>> _renames = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<(DateTime Time, string? NewPath)>> _truncates = new(StringComparer.OrdinalIgnoreCase);
    // Writes the collector saw but does not record (excluded users, processes, system accounts): they
    // explain a create or truncation as much as a recorded write
    private readonly Dictionary<string, List<(DateTime Time, string? NewPath)>> _claims = new(StringComparer.OrdinalIgnoreCase);
    // Opens for writing (event 4656, when that is audited): who created or truncated a file. Who is null
    // for an open by an excluded user or process.
    private readonly Dictionary<string, List<(DateTime Time, AccessRecord? Who)>> _opens = new(StringComparer.OrdinalIgnoreCase);
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

    // Creates or truncations still waiting to be explained: Release must run again even without new events
    public bool HasWaitingFacts
    {
        get { lock (_gate) return _creates.Count > 0 || _truncates.Count > 0; }
    }

    public int FactCount
    {
        get { lock (_gate) return _factCount; }
    }

    // Whether a file renamed from a temporary (excluded) name to this path is recorded, as a write of it:
    // the name is not excluded and the path is monitored. Set by the collector.
    public Func<string, bool> TakesContentAt { get; set; } = _ => false;

    // Whether a create or truncation of this file that no write explains is recorded: the name is not
    // excluded, the path is monitored for writes and is a file. Set by the collector.
    public Func<string, bool> TakesUnexplainedAt { get; set; } = _ => false;

    // The time up to which the Security log has been processed (now, when nothing is waiting). Set by the
    // collector; a create is unexplained only once the writes around it cannot arrive any more.
    public DateTime SecurityLogUtc
    {
        get { lock (_gate) return _securityLogUtc; }
        set { lock (_gate) _securityLogUtc = value; }
    }
    private DateTime _securityLogUtc = DateTime.MinValue;

    public void AddCreate(string path, DateTime timeUtc) => AddFact(_creates, path, timeUtc, null);

    public void AddRename(string oldPath, string newPath, DateTime timeUtc) => AddFact(_renames, oldPath, timeUtc, newPath);

    public void AddTruncate(string path, DateTime timeUtc) => AddFact(_truncates, path, timeUtc, null);

    public void Claim(string path, DateTime timeUtc) => AddFact(_claims, path, timeUtc, null);

    public void AddOpen(string path, DateTime timeUtc, AccessRecord? who)
    {
        lock (_gate)
        {
            if (!_opens.TryGetValue(path, out var list)) _opens[path] = list = [];
            list.Add((timeUtc, who));
            _factCount++;
            if (_factCount > MaxFacts) Prune(force: true);
        }
    }

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
    // a rename gets its new name, a permission change may be the one made while a file was created.
    // Denied records and folder writes / permission changes never are.
    public static bool NeedsCorrelation(AccessRecord r) =>
        !r.Denied && r.AccessType is AccessTypes.Rename or AccessTypes.Write or AccessTypes.Permission
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
                if (Resolve(h.Record)) released.Add(h.Record);
                n++;
            }
            _held.RemoveRange(0, n);
            released.AddRange(Unexplained(force));
            if (nowUtc - _lastPrune >= TimeSpan.FromSeconds(30)) { _lastPrune = nowUtc; Prune(force: false); }
            return released;
        }
    }

    // Creates and truncations no write took (Resolve) and no skipped write claimed, once a write could not
    // come any more: both sources past the fact by CreateLead, and no held record from before that time.
    // force: shutdown, everything still known.
    private List<AccessRecord> Unexplained(bool force)
    {
        var known = _caughtUpUtc < _securityLogUtc ? _caughtUpUtc : _securityLogUtc;
        if (_held.Count > 0 && _held[0].Record.AccessTime < known) known = _held[0].Record.AccessTime;
        var horizon = known > DateTime.MinValue + CreateLead + CatchUpSlack ? known - CreateLead - CatchUpSlack : DateTime.MinValue;
        var records = new List<AccessRecord>();
        foreach (var (facts, type) in new[] { (_creates, AccessTypes.Create), (_truncates, AccessTypes.Write) })
        {
            foreach (var path in facts.Keys.ToList())
            {
                var list = facts[path];
                for (var i = list.Count - 1; i >= 0; i--)
                {
                    var time = list[i].Time;
                    if (!force && time > horizon) continue;
                    list.RemoveAt(i);
                    _factCount--;
                    if (HasFact(_claims, path, time - CreateLag, time + CreateLead) || !TakesUnexplainedAt(path)) continue;
                    if (Unexplained(path, time, type) is { } r) records.Add(r);
                }
                if (list.Count == 0) facts.Remove(path);
            }
        }
        return records.OrderBy(r => r.AccessTime).ToList();
    }

    private AccessRecord? Unexplained(string path, DateTime time, string type)
    {
        AccessRecord? who = null;
        if (_opens.TryGetValue(path, out var opens))
        {
            var near = opens.Where(o => (o.Time - time).Duration() <= OpenMatch).OrderBy(o => (o.Time - time).Duration()).ToList();
            if (near.Count > 0)
            {
                who = near[0].Who;
                if (who == null) return null; // opened by an excluded user or process
            }
        }
        return new AccessRecord
        {
            FilePath = path,
            FileName = Path.GetFileName(path),
            FolderPath = Path.GetDirectoryName(path) ?? path,
            UserName = who?.UserName ?? UnknownUser,
            AccessType = type,
            AccessTime = time,
            ClientIp = who?.ClientIp,
            ClientMachine = who?.ClientMachine,
            ServerName = who?.ServerName ?? Environment.MachineName,
        };
    }

    // False: the record is dropped (a temporary name that did not become a recorded one)
    private bool Resolve(AccessRecord r)
    {
        var t = r.AccessTime;
        if (r.AccessType == AccessTypes.Write)
        {
            // Consumed, so a later write to the same file stays a write
            if (TakeNearest(_creates, r.FilePath, t - CreateLead, t + CreateLag, t) != null)
                r.AccessType = AccessTypes.Create;
            // A truncation before the write (a save that overwrites the file) is part of it
            TakeNearest(_truncates, r.FilePath, t - CreateLead, t + CreateLag, t);
        }
        else if (r.AccessType == AccessTypes.Permission)
        {
            // Only looked at, not consumed: the write that follows needs the fact to become the Create
            if (HasFact(_creates, r.FilePath, t - CreateLead, t + CreateLag)) r.AtCreation = true;
        }
        else if (r.AccessType == AccessTypes.Rename)
        {
            if (TakeNearest(_renames, r.FilePath, t - RenameLead, t + RenameLag, t) is { } fact)
                r.NewPath = fact.NewPath;
            if (r.ExcludedName)
            {
                // A file written under a temporary name and renamed into place: new content under that name
                if (r.NewPath is not { } path || !TakesContentAt(path)) return false;
                r.FilePath = path;
                r.FileName = Path.GetFileName(path);
                r.FolderPath = Path.GetDirectoryName(path) ?? path;
                r.AccessType = AccessTypes.Write;
                r.NewPath = null;
                r.ExcludedName = false;
            }
        }
        return true;
    }

    private static bool HasFact(Dictionary<string, List<(DateTime Time, string? NewPath)>> facts, string path, DateTime from, DateTime to) =>
        facts.TryGetValue(path, out var list) && list.Any(f => f.Time >= from && f.Time <= to);

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
            var all = _creates.Values.Concat(_renames.Values).Concat(_truncates.Values).Concat(_claims.Values).SelectMany(l => l)
                .Select(f => f.Time).Concat(_opens.Values.SelectMany(l => l).Select(o => o.Time)).Order().ToList();
            limit = all[all.Count / 2];
        }
        Prune(_creates, limit);
        Prune(_renames, limit);
        Prune(_truncates, limit);
        Prune(_claims, limit);
        foreach (var path in _opens.Keys.ToList())
        {
            var list = _opens[path];
            _factCount -= list.RemoveAll(o => o.Time < limit);
            if (list.Count == 0) _opens.Remove(path);
        }
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
