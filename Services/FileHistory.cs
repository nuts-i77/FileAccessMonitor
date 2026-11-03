using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Services;

// Position of a record in time: (time, id) is strictly increasing, so records of the same second are ordered by Id
public readonly record struct HistoryKey(DateTime Time, long Id) : IComparable<HistoryKey>
{
    public int CompareTo(HistoryKey other) => Time != other.Time ? Time.CompareTo(other.Time) : Id.CompareTo(other.Id);
    public static bool operator <(HistoryKey a, HistoryKey b) => a.CompareTo(b) < 0;
    public static bool operator >(HistoryKey a, HistoryKey b) => a.CompareTo(b) > 0;
    public static bool operator <=(HistoryKey a, HistoryKey b) => a.CompareTo(b) <= 0;
    public static bool operator >=(HistoryKey a, HistoryKey b) => a.CompareTo(b) >= 0;
    public HistoryKey Next => this with { Id = Id + 1 };
    public HistoryKey Previous => this with { Id = Id - 1 };
}

// The part of an AccessRecord the history needs
public sealed record HistoryRecord(long Id, DateTime Time, string Type, bool Denied, bool IsFolder, string User,
    string Path, string? NewPath, string? Detail, string? ClientIp, string? ClientMachine)
{
    public HistoryKey Key => new(Time, Id);
}

// Where the history reads records from. Paths are compared like the platform does (Windows paths
// ignore case); every query is on one file server. Records marked Denied never changed anything.
public interface IHistorySource
{
    // The record of the path the user clicked: the newest at or before `at` (the oldest when none is that
    // old), or the newest of all when `at` is null
    Task<HistoryRecord?> AnchorAsync(string server, string path, DateTime? at);
    // The newest Create or Delete of the path between notBefore and notAfter
    Task<HistoryRecord?> BoundaryAsync(string server, string path, HistoryKey notAfter, DateTime? notBefore);
    // Renames whose destination is one of the paths, newest first
    Task<List<HistoryRecord>> RenamedToAsync(string server, IReadOnlyList<string> paths, HistoryKey notAfter, DateTime? notBefore, int limit);
    // Renames and deletes of the paths from the key on, oldest first
    Task<List<HistoryRecord>> EndsAsync(string server, IReadOnlyList<string> paths, HistoryKey notBefore, int limit);
    // Records of one path between the keys (inclusive; null = unbounded), oldest first; the newest `limit` when there are more
    Task<List<HistoryRecord>> RecordsAsync(string server, string path, HistoryKey? from, HistoryKey? to, int limit);
}

public record HistoryRequest(string Server, string Path, DateTime? At, int Days = 0, bool Collapse = true, int MaxEvents = FileHistory.DefaultEvents);

public enum HistoryStatus { Ok, None, Outside }

public record HistoryOutcome(HistoryStatus Status, HistoryResult? Result);

public class HistoryResult
{
    public string Server { get; set; } = "";
    public string Path { get; set; } = "";
    public DateTime AnchorTime { get; set; }
    public string Origin { get; set; } = "unknown";   // created | renamedIn | unknown | outOfScope
    public string End { get; set; } = "exists";       // exists | deleted | unknownDestination | outOfScope | hopLimit
    public HistoryTruncated Truncated { get; set; } = new();
    public List<HistoryPath> Paths { get; set; } = [];
    public List<HistoryStep> Steps { get; set; } = [];
}

public class HistoryTruncated
{
    public bool Events { get; set; }
    public bool Hops { get; set; }
    // The walk stopped at the `days` limit although the file came from further back
    public bool Window { get; set; }
}

public record HistoryPath(string Path, DateTime? From, DateTime? To, bool Visible);

public class HistoryStep
{
    public string Kind { get; set; } = "";   // create | read | write | rename | move | permission | delete | denied | gap
    public DateTime? Time { get; set; }
    public string? User { get; set; }
    public string? Type { get; set; }
    public bool Denied { get; set; }
    public int Count { get; set; } = 1;
    public DateTime? FirstTime { get; set; }
    public DateTime? LastTime { get; set; }
    public string? Path { get; set; }
    public string? NewPath { get; set; }
    public string? Detail { get; set; }
    public string? ViaFolder { get; set; }
    public long? RecordId { get; set; }
    public string? ClientIp { get; set; }
    public string? ClientMachine { get; set; }
    public HistoryGap? Gap { get; set; }
}

public record HistoryGap(string Reason);   // outOfScope | unknownDestination | unknownOrigin

// Follows a file (or folder) through renames, moves and renames of its parent folders and returns what
// happened to it, oldest first. Pure logic over IHistorySource, so it is tested without a database.
//
// The path is split into "segments": the stretches of time in which the file had one path. Backward
// from the clicked record the walk looks for the rename that brought the file to that path (a rename
// of the file or of a parent folder), unless the file was created or a file of that name was deleted
// after it; forward it looks for the first rename or delete of the file or of a parent folder.
// The walk runs on unscoped queries (it has to cross the boundary of a viewer's scope to know that
// something happened), only the output is limited to the scope.
public class FileHistory(IHistorySource source, Func<DateTime> utcNow)
{
    public const int MaxHops = 50;
    public const int MaxDepth = 32;
    public const int DefaultEvents = 500;
    public const int MaxEvents = 2000;
    public const int FetchLimit = 20000;
    private const int LookupLimit = 200;
    private static readonly TimeSpan ReadGap = TimeSpan.FromMinutes(10);

    private sealed class Seg
    {
        public string Path = "";
        public HistoryKey? Start;          // inclusive; null = as far back as there are records
        public HistoryKey? End;            // inclusive; null = still open
        public HistoryRecord? EndRec;      // the rename or delete that ended it
        public string? EndVia;             // the parent folder (old path) when EndRec is a folder's record
        public bool BeganByRename;
        public List<HistoryRecord> Records = [];
    }

    public async Task<HistoryOutcome> BuildAsync(HistoryRequest req, IReadOnlyList<ScopeEntry>? scope)
    {
        var server = req.Server;
        var start = req.Path;
        bool Visible(string p) => scope == null || AccessScope.Contains(scope, server, p);
        if (!Visible(start)) return new HistoryOutcome(HistoryStatus.Outside, null);

        var maxEvents = Math.Clamp(req.MaxEvents, 1, MaxEvents);
        var truncated = new HistoryTruncated();

        // The record the walk starts at: a record of the path, or else the rename that led to it
        var anchor = await source.AnchorAsync(server, start, req.At);
        if (anchor == null)
        {
            var into = (await source.RenamedToAsync(server, [start], new HistoryKey(DateTime.MaxValue, long.MaxValue), null, 1)).FirstOrDefault();
            if (into == null) return new HistoryOutcome(HistoryStatus.None, null);
            anchor = into;
        }
        var anchorKey = anchor.Key;
        // The `days` limit counts back from now, but never cuts the record the user asked for
        DateTime? lower = req.Days > 0 ? Min(utcNow().AddDays(-req.Days), anchor.Time) : null;

        var seg0 = new Seg { Path = start };
        var segs = new List<Seg> { seg0 };
        var visited = new HashSet<(string, HistoryKey)>();
        string origin;

        // ---- backward: how did the file come to this path?
        // A delete record that is the clicked one ends the life; it is not the beginning of it
        var back = anchor.Type == "Delete" && !anchor.Denied && Same(anchor.Path, start) ? anchorKey.Previous : anchorKey;
        var cur = seg0;
        while (true)
        {
            var path = cur.Path;
            var boundary = await source.BoundaryAsync(server, path, back, null);
            var into = (await source.RenamedToAsync(server, WithAncestors(path), back, null, LookupLimit))
                .Where(r => r.Type == "Rename" && !r.Denied && r.NewPath != null && (Same(r.NewPath, path) || (r.IsFolder && IsAncestor(r.NewPath, path))))
                .OrderByDescending(r => r.Key).FirstOrDefault();

            if (boundary != null && (into == null || boundary.Key > into.Key))
            {
                // created here (a delete means: older records belong to an older file of this name)
                cur.Start = boundary.Type == "Create" ? boundary.Key : boundary.Key.Next;
                origin = boundary.Type == "Create" ? "created" : "unknown";
                break;
            }
            if (into == null)
            {
                origin = "unknown";
                break;
            }
            cur.BeganByRename = true;
            cur.Start = into.Key.Next;
            var viaFolder = !Same(into.NewPath!, path);
            if (segs.Count >= MaxHops || !visited.Add((Fold(path), into.Key)))
            {
                truncated.Hops = true;
                origin = "renamedIn";
                break;
            }
            if (lower != null && into.Time < lower)
            {
                truncated.Window = true;
                origin = "renamedIn";
                break;
            }
            var prev = new Seg
            {
                Path = viaFolder ? Replace(path, into.NewPath!, into.Path) : into.Path,
                End = into.Key, EndRec = into, EndVia = viaFolder ? into.Path : null,
            };
            segs.Insert(0, prev);
            cur = prev;
            back = into.Key.Previous;
        }

        // ---- forward: where did it go?
        string end;
        var last = seg0;
        var fromKey = anchorKey;
        visited.Clear();
        while (true)
        {
            var path = last.Path;
            var e = (await source.EndsAsync(server, WithAncestors(path), fromKey, LookupLimit))
                .FirstOrDefault(r => !r.Denied && (Same(r.Path, path) || (r.IsFolder && IsAncestor(r.Path, path))));
            if (e == null)
            {
                end = "exists";
                break;
            }
            var viaFolder = !Same(e.Path, path);
            last.End = e.Key;
            last.EndRec = e;
            last.EndVia = viaFolder ? e.Path : null;
            if (e.Type == "Delete")
            {
                end = "deleted";
                break;
            }
            if (e.NewPath == null)
            {
                end = "unknownDestination";
                break;
            }
            var next = viaFolder ? Replace(path, e.Path, e.NewPath) : e.NewPath;
            if (segs.Count >= MaxHops || !visited.Add((Fold(next), e.Key)))
            {
                end = "hopLimit";
                truncated.Hops = true;
                break;
            }
            var seg = new Seg { Path = next, Start = e.Key.Next, BeganByRename = true };
            segs.Add(seg);
            last = seg;
            fromKey = e.Key.Next;
        }

        // ---- the records of each segment
        foreach (var seg in segs)
        {
            var from = seg.Start;
            if (lower != null && (from == null || from.Value.Time < lower))
                from = new HistoryKey(lower.Value, 0);
            var records = await source.RecordsAsync(server, seg.Path, from, seg.End, FetchLimit + 1);
            if (records.Count > FetchLimit)
            {
                records.RemoveRange(0, records.Count - FetchLimit);
                truncated.Events = true;
            }
            seg.Records = records.Where(r => Same(r.Path, seg.Path)).OrderBy(r => r.Key).ToList();
        }

        // ---- the output, limited to the viewer's scope
        var result = new HistoryResult
        {
            Server = server, Path = start, AnchorTime = Utc(anchor.Time), Origin = origin, End = end, Truncated = truncated,
        };
        string? Shown(string? p) => p != null && Visible(p) ? p : null;

        var steps = new List<HistoryStep>();
        var inGap = false;
        for (var i = 0; i < segs.Count; i++)
        {
            var seg = segs[i];
            if (!Visible(seg.Path))
            {
                if (!inGap) steps.Add(Gap("outOfScope"));
                inGap = true;
                if (i == 0) result.Origin = "outOfScope";
                if (i == segs.Count - 1) result.End = "outOfScope";
                continue;
            }
            inGap = false;
            result.Paths.Add(new HistoryPath(seg.Path, seg.Start?.Time, seg.End?.Time, true));
            if (i == 0 && origin == "unknown") steps.Add(Gap("unknownOrigin"));

            foreach (var r in seg.Records)
                steps.Add(StepOf(r, Shown));
            if (seg.EndVia != null && seg.EndRec is { } viaRec && !seg.Records.Any(r => r.Id == viaRec.Id))
            {
                // the file itself has no record: its parent folder was renamed or deleted
                var next = i + 1 < segs.Count ? segs[i + 1].Path : null;
                steps.Add(new HistoryStep
                {
                    Kind = viaRec.Type == "Delete" ? "delete" : "move", Time = Utc(viaRec.Time), User = viaRec.User, Type = viaRec.Type,
                    Path = seg.Path, NewPath = viaRec.Type == "Delete" ? null : Shown(next),
                    ViaFolder = Shown(seg.EndVia), RecordId = viaRec.Id, ClientIp = viaRec.ClientIp, ClientMachine = viaRec.ClientMachine,
                });
            }
        }
        if (end == "unknownDestination" && Visible(segs[^1].Path)) steps.Add(Gap("unknownDestination"));

        if (req.Collapse) steps = CollapseReads(steps);
        if (steps.Count > maxEvents)
        {
            truncated.Events = true;
            var keepFirst = steps[0].Kind is "create" or "gap";
            steps = keepFirst
                ? [steps[0], .. steps.Skip(steps.Count - (maxEvents - 1))]
                : steps.Skip(steps.Count - maxEvents).ToList();
        }
        result.Steps = steps;
        return new HistoryOutcome(HistoryStatus.Ok, result);
    }

    private static HistoryStep Gap(string reason) => new() { Kind = "gap", Gap = new HistoryGap(reason) };

    private static HistoryStep StepOf(HistoryRecord r, Func<string?, string?> shown)
    {
        var kind = r.Denied ? "denied" : r.Type switch
        {
            "Create" => "create",
            "Read" => "read",
            "Write" => "write",
            "Permission" => "permission",
            "Delete" => "delete",
            // a destination the viewer may not see is shown as a move without one
            "Rename" => r.NewPath != null && shown(r.NewPath) != null && Same(ParentOf(r.Path), ParentOf(r.NewPath)) ? "rename" : "move",
            _ => r.Type.ToLowerInvariant(),
        };
        return new HistoryStep
        {
            Kind = kind, Time = Utc(r.Time), User = r.User, Type = r.Type, Denied = r.Denied, Path = r.Path,
            NewPath = shown(r.NewPath), Detail = r.Detail, RecordId = r.Id, ClientIp = r.ClientIp, ClientMachine = r.ClientMachine,
        };
    }

    // Reads of one user with less than ten minutes between them and nothing else in between become one step
    private static List<HistoryStep> CollapseReads(List<HistoryStep> steps)
    {
        var result = new List<HistoryStep>();
        foreach (var s in steps)
        {
            if (s.Kind == "read" && result.Count > 0 && result[^1] is { Kind: "read" } p
                && p.User == s.User && p.Path == s.Path && s.Time - (p.LastTime ?? p.Time) < ReadGap)
            {
                p.FirstTime ??= p.Time;
                p.LastTime = s.Time;
                p.Count++;
                continue;
            }
            result.Add(s);
        }
        return result;
    }

    private static DateTime Utc(DateTime t) => DateTime.SpecifyKind(t, DateTimeKind.Utc);
    private static DateTime Min(DateTime a, DateTime b) => a < b ? a : b;

    // ---- path helpers: Windows paths ignore case, Unix paths do not

    private static bool Same(string a, string b) => a.Equals(b, PathText.ComparisonOf(a));
    private static string Fold(string p) => PathText.IsUnix(p) ? p : p.ToUpperInvariant();

    private static int RootLength(string path)
    {
        if (PathText.IsUnix(path)) return 1;
        if (path.StartsWith(@"\\"))
        {
            // \\server\share
            var i = path.IndexOf('\\', 2);
            if (i < 0) return path.Length;
            var j = path.IndexOf('\\', i + 1);
            return j < 0 ? path.Length : j;
        }
        return path.Length > 2 && path[1] == ':' ? 3 : 0;
    }

    private static string ParentOf(string path)
    {
        var sep = PathText.SeparatorOf(path);
        var i = path.LastIndexOf(sep);
        return i <= 0 ? "" : path[..i];
    }

    // The folders above the path, deepest first, without the drive or share root
    internal static List<string> Ancestors(string path)
    {
        var sep = PathText.SeparatorOf(path);
        var root = RootLength(path);
        var list = new List<string>();
        var cur = path;
        while (list.Count < MaxDepth)
        {
            var i = cur.LastIndexOf(sep);
            if (i < root || i <= 0) break;
            cur = cur[..i];
            if (cur.Length <= root) break;
            list.Add(cur);
        }
        return list;
    }

    private static List<string> WithAncestors(string path) => [path, .. Ancestors(path)];

    private static bool IsAncestor(string folder, string path) =>
        path.Length > folder.Length && path.StartsWith(folder + PathText.SeparatorOf(path), PathText.ComparisonOf(path));

    // path lies under oldFolder: the same place under newFolder
    private static string Replace(string path, string oldFolder, string newFolder) =>
        newFolder.TrimEnd(PathText.SeparatorOf(newFolder)) + path[oldFolder.Length..];
}

// Reads the history from the database. SQLite compares text exactly, so Windows paths (which Windows
// matches case-insensitively) are looked up as the recorded text and its upper and lower case form on
// the FilePath index, and through a NOCASE index on NewPath; the algorithm then compares like Windows.
public class EfHistorySource(AccessDbContext db) : IHistorySource
{
    private IQueryable<AccessRecord> Of(string server) => db.AccessRecords.AsNoTracking().Where(r => r.ServerName == server);

    private static List<string> Variants(IEnumerable<string> paths) => paths
        .SelectMany(p => PathText.IsUnix(p) ? [p] : new[] { p, p.ToUpperInvariant(), p.ToLowerInvariant() })
        .Distinct().ToList();

    private static HistoryRecord Map(AccessRecord r) => new(r.Id, r.AccessTime, r.AccessType, r.Denied, r.IsFolder, r.UserName,
        r.FilePath, r.NewPath, r.Detail, r.ClientIp, r.ClientMachine);

    public async Task<HistoryRecord?> AnchorAsync(string server, string path, DateTime? at)
    {
        var paths = Variants([path]);
        var q = Of(server).Where(r => paths.Contains(r.FilePath));
        if (at is { } t)
        {
            var limit = t.AddMilliseconds(1);   // the browser keeps milliseconds only
            var r = await q.Where(x => x.AccessTime <= limit).OrderByDescending(x => x.AccessTime).ThenByDescending(x => x.Id).FirstOrDefaultAsync()
                ?? await q.OrderBy(x => x.AccessTime).ThenBy(x => x.Id).FirstOrDefaultAsync();
            return r == null ? null : Map(r);
        }
        var newest = await q.OrderByDescending(x => x.AccessTime).ThenByDescending(x => x.Id).FirstOrDefaultAsync();
        return newest == null ? null : Map(newest);
    }

    public async Task<HistoryRecord?> BoundaryAsync(string server, string path, HistoryKey notAfter, DateTime? notBefore)
    {
        var paths = Variants([path]);
        var (t, id) = (notAfter.Time, notAfter.Id);
        var q = Of(server).Where(r => paths.Contains(r.FilePath) && !r.Denied && (r.AccessType == "Create" || r.AccessType == "Delete")
                                      && (r.AccessTime < t || (r.AccessTime == t && r.Id <= id)));
        if (notBefore is { } nb) q = q.Where(r => r.AccessTime >= nb);
        var rec = await q.OrderByDescending(r => r.AccessTime).ThenByDescending(r => r.Id).FirstOrDefaultAsync();
        return rec == null ? null : Map(rec);
    }

    public async Task<List<HistoryRecord>> RenamedToAsync(string server, IReadOnlyList<string> paths, HistoryKey notAfter, DateTime? notBefore, int limit)
    {
        var list = await RenamedToQuery(server, paths, notAfter, notBefore)
            .OrderByDescending(r => r.AccessTime).ThenByDescending(r => r.Id).Take(limit).ToListAsync();
        // NOCASE found the rows; Unix paths are compared exactly
        return list.Select(Map)
            .Where(r => paths.Any(p => r.NewPath!.Equals(p, PathText.ComparisonOf(p))))
            .ToList();
    }

    // Looks the destinations up in IX_AccessRecords_NewPath (NOCASE, partial). The other conditions are written
    // as expressions (+column) so that SQLite does not pick another index for them over this one.
    internal IQueryable<AccessRecord> RenamedToQuery(string server, IReadOnlyList<string> paths, HistoryKey notAfter, DateTime? notBefore)
    {
        var placeholders = string.Join(", ", paths.Select((_, i) => "{" + (i + 1) + "}"));
        // (the values are parameters: FromSql turns the format arguments into them)
        var sql = System.Runtime.CompilerServices.FormattableStringFactory.Create(
            $"SELECT * FROM \"AccessRecords\" WHERE \"NewPath\" IS NOT NULL AND \"NewPath\" COLLATE NOCASE IN ({placeholders}) "
            + "AND +\"ServerName\" = {0} AND +\"AccessType\" = 'Rename' AND +\"Denied\" = 0",
            [server, .. paths]);
        var (t, id) = (notAfter.Time, notAfter.Id);
        var rows = db.AccessRecords.FromSql(sql).AsNoTracking().Where(r => r.AccessTime < t || (r.AccessTime == t && r.Id <= id));
        if (notBefore is { } nb) rows = rows.Where(r => r.AccessTime >= nb);
        return rows;
    }

    public async Task<List<HistoryRecord>> EndsAsync(string server, IReadOnlyList<string> paths, HistoryKey notBefore, int limit)
    {
        var all = Variants(paths);
        var (t, id) = (notBefore.Time, notBefore.Id);
        var list = await Of(server).Where(r => all.Contains(r.FilePath) && !r.Denied && (r.AccessType == "Rename" || r.AccessType == "Delete")
                                                && (r.AccessTime > t || (r.AccessTime == t && r.Id >= id)))
            .OrderBy(r => r.AccessTime).ThenBy(r => r.Id).Take(limit).ToListAsync();
        return list.Select(Map).ToList();
    }

    public async Task<List<HistoryRecord>> RecordsAsync(string server, string path, HistoryKey? from, HistoryKey? to, int limit)
    {
        var paths = Variants([path]);
        var q = Of(server).Where(r => paths.Contains(r.FilePath));
        if (from is { } f)
        {
            var (t, id) = (f.Time, f.Id);
            q = q.Where(r => r.AccessTime > t || (r.AccessTime == t && r.Id >= id));
        }
        if (to is { } e)
        {
            var (t, id) = (e.Time, e.Id);
            q = q.Where(r => r.AccessTime < t || (r.AccessTime == t && r.Id <= id));
        }
        var list = await q.OrderByDescending(r => r.AccessTime).ThenByDescending(r => r.Id).Take(limit).ToListAsync();
        list.Reverse();
        return list.Select(Map).ToList();
    }
}
