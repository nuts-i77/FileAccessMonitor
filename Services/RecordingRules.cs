using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using FileAccessMonitor.Models;

namespace FileAccessMonitor.Services;

// Stored under "Recording" in settings.json and edited on the Settings tab.
// When the key is missing (new install or upgrade), the defaults below apply.
public class RecordingSettings
{
    public const string SettingsKey = "Recording";
    public static readonly string[] DefaultFilePatterns = ["Thumbs.db", "desktop.ini", "~$*", "*.tmp"];
    public const int DefaultMergeReadMinutes = 5;
    public const int MaxMergeReadMinutes = 1440;

    public List<string> ExcludeFilePatterns { get; set; } = [.. DefaultFilePatterns];
    public List<string> ExcludeUsers { get; set; } = [];
    public List<string> ExcludeProcesses { get; set; } = [];
    // Reads of the same file by the same user within this many minutes of the previous one
    // are recorded once (0 = record every read).
    public int MergeReadMinutes { get; set; } = DefaultMergeReadMinutes;

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public static RecordingSettings Load() =>
        SettingsStore.Load()[SettingsKey]?.Deserialize<RecordingSettings>(JsonOptions) ?? new RecordingSettings();

    public void Save() =>
        SettingsStore.Update(root => root[SettingsKey] = JsonSerializer.SerializeToNode(this));
}

// Exclusion patterns compiled once per settings change. Patterns are matched against the whole
// name, case-insensitively, with * and ? as wildcards.
public class RecordingRules
{
    private readonly Regex[] _files;
    private readonly Regex[] _users;
    private readonly Regex[] _processes;

    public RecordingRules(RecordingSettings settings)
    {
        Settings = settings;
        _files = Compile(settings.ExcludeFilePatterns);
        _users = Compile(settings.ExcludeUsers);
        _processes = Compile(settings.ExcludeProcesses);
    }

    public RecordingSettings Settings { get; }
    public TimeSpan MergeReadWindow => TimeSpan.FromMinutes(Math.Max(0, Settings.MergeReadMinutes));

    public bool IsExcludedFile(string fileName) => AnyMatch(_files, fileName);

    // "DOMAIN\user" patterns match the full name; plain "user" patterns match the name in any domain.
    public bool IsExcludedUser(string fullUserName)
    {
        var shortName = fullUserName[(fullUserName.LastIndexOf('\\') + 1)..];
        return AnyMatch(_users, fullUserName) || AnyMatch(_users, shortName);
    }

    public bool IsExcludedProcess(string processName) =>
        processName.Length > 0 && AnyMatch(_processes, processName);

    internal static Regex WildcardToRegex(string pattern) =>
        new("^" + Regex.Escape(pattern.Trim()).Replace(@"\*", ".*").Replace(@"\?", ".") + "$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static Regex[] Compile(IEnumerable<string> patterns) =>
        patterns.Where(p => !string.IsNullOrWhiteSpace(p)).Select(WildcardToRegex).ToArray();

    private static bool AnyMatch(Regex[] patterns, string value) => patterns.Any(r => r.IsMatch(value));
}

// Records repeated reads of the same file by the same user once. The window slides: each read
// (recorded or not) restarts it, so a long video with seeks counts as one read.
public class ReadMerger
{
    private readonly Dictionary<(string User, string Path), DateTime> _lastRead = new();
    private DateTime _newest = DateTime.MinValue;

    public bool ShouldRecord(AccessRecord record, TimeSpan window)
    {
        if (record.AccessType != "Read" || window <= TimeSpan.Zero) return true;

        var key = (record.UserName.ToUpperInvariant(), record.FilePath.ToUpperInvariant());
        var time = record.AccessTime;
        var merged = _lastRead.TryGetValue(key, out var last) && (time - last).Duration() < window;
        _lastRead[key] = merged && last > time ? last : time;

        if (time > _newest) _newest = time;
        if (_lastRead.Count > 100_000) Prune(window);
        return !merged;
    }

    private void Prune(TimeSpan window)
    {
        foreach (var key in _lastRead.Where(kv => _newest - kv.Value >= window).Select(kv => kv.Key).ToList())
            _lastRead.Remove(key);
    }
}

// Folders seen recently, as a folder or as the parent of a file. A folder can already be gone when
// its deletion is processed; its contents are deleted before it, so it is known from them.
public class RecentFolders
{
    private const int MaxCount = 50_000;
    private readonly HashSet<string> _folders = new(StringComparer.OrdinalIgnoreCase);

    public void Add(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        if (_folders.Count >= MaxCount) _folders.Clear();
        _folders.Add(path);
    }

    public bool Contains(string path) => _folders.Contains(path);
}

// Tells deletions apart from renames and moves. Both open the file with DELETE access (event 4663),
// but only a deletion is followed by event 4660 for the same handle. A DELETE access is therefore
// held until either 4660 arrives (deleted) or a short time passes without it (renamed or moved).
public class DeleteTracker
{
    public static readonly TimeSpan ConfirmTimeout = TimeSpan.FromSeconds(2);

    private sealed record Pending(AccessRecord Record, string? OtherType, IReadOnlySet<string> EventTypes, DateTime AddedUtc);

    private readonly Dictionary<(string ProcessId, string HandleId), Pending> _pending = new();
    private readonly Func<string, bool> _pathExists;

    public DeleteTracker(Func<string, bool> pathExists) => _pathExists = pathExists;

    public bool HasPending => _pending.Count > 0;

    // otherType: what the same access would be without the DELETE right (Read/Write/null).
    // eventTypes: the types monitored for the record's folder.
    public void Add(string processId, string handleId, AccessRecord record, string? otherType,
        IReadOnlySet<string> eventTypes, DateTime nowUtc)
    {
        var key = (processId, handleId);
        if (_pending.Remove(key, out var previous))
            Resolved.Add(previous); // handle id reused: the earlier access was not a deletion
        _pending[key] = new Pending(record, otherType, eventTypes, nowUtc);
    }

    // Event 4660 (object deleted). Returns the deleted file's record, if one was pending.
    public AccessRecord? Confirm(string processId, string handleId)
    {
        if (!_pending.Remove((processId, handleId), out var p)) return null;
        p.Record.AccessType = "Delete";
        return p.EventTypes.Contains("Delete") ? p.Record : null;
    }

    // Resolves accesses that got no 4660 in time: by the time of the newest event seen (catching up
    // on old events) or by the clock (live). With force, resolves everything (shutdown).
    public List<AccessRecord> Expire(DateTime newestEventUtc, DateTime nowUtc, bool force = false)
    {
        var expired = _pending
            .Where(kv => force
                || newestEventUtc - kv.Value.Record.AccessTime >= ConfirmTimeout
                || nowUtc - kv.Value.AddedUtc >= ConfirmTimeout)
            .ToList();
        foreach (var kv in expired)
        {
            _pending.Remove(kv.Key);
            Resolved.Add(kv.Value);
        }

        var records = new List<AccessRecord>();
        foreach (var p in Resolved)
            if (Resolve(p) is { } r) records.Add(r);
        Resolved.Clear();
        return records.OrderBy(r => r.AccessTime).ToList();
    }

    private List<Pending> Resolved { get; } = [];

    // Not deleted: if nothing is at the old path any more, the file was renamed or moved away.
    // If something is (Office saves by renaming the old file away and a new one into its place),
    // the access counts as whatever it was apart from DELETE, or as a write.
    private AccessRecord? Resolve(Pending p)
    {
        string type;
        if (!_pathExists(p.Record.FilePath))
        {
            type = "Rename";
            if (!p.EventTypes.Contains("Delete")) return null; // renames follow the Delete setting
        }
        else if (p.Record.IsFolder)
        {
            return null; // folder still there: neither deleted nor renamed
        }
        else
        {
            type = p.OtherType ?? "Write";
            if (!p.EventTypes.Contains(type)) return null;
        }
        p.Record.AccessType = type;
        return p.Record;
    }
}
