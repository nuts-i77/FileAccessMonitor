using System.Text.RegularExpressions;
using FileAccessMonitor.Models;

namespace FileAccessMonitor.Services;

// Ransomware-like behaviour: WindowMinutes is the window for all three rules. Settings.json only
// (see AlertSettings); kept free of collections so that record equality tells when rules changed.
public record RansomwareRules(
    bool Enabled = true, int WindowMinutes = 2, int SameExtensionRenames = 20, int BurstWrites = 100,
    int BurstRenames = 50, int NoteFolders = 3, int CooldownMinutes = 30);

public record AlertRules(
    int DeleteThreshold, int WriteThreshold, int WindowMinutes, int CooldownMinutes, int ReadThreshold = 0,
    int DeniedThreshold = 0, RansomwareRules? Ransomware = null);

public record Alert(
    string AccessType, string UserName, int Count, int WindowMinutes,
    DateTime FromUtc, DateTime ToUtc, string? ClientIp, string? ClientMachine,
    IReadOnlyList<(string Folder, int Count)> TopFolders, IReadOnlyList<string> SamplePaths,
    string ServerName = "", // file server(s) the accesses happened on
    string Rule = "",       // Ransomware: extension | burst | note
    string? Detail = null,  // Ransomware: what matched, e.g. ".locked (34 files)"
    string Priority = "Normal");

// Detects bursts: one user deleting, writing, reading or being refused at least N files within M
// minutes, and ransomware-like behaviour (see RansomwareRules).
// Uses the event time, so a backlog read after a restart is judged by when it happened.
// Not thread-safe; called only from the collector's single consumer.
public class AlertDetector(AlertRules rules)
{
    private readonly Dictionary<(string User, string Type), Queue<AccessRecord>> _windows = new();
    private readonly Dictionary<(string User, string Type), DateTime> _lastAlert = new();
    private readonly Dictionary<(string Server, string User), RansomwareWindow> _ransomware = new();
    private readonly Dictionary<(string Server, string User, string Rule), DateTime> _lastRansomwareAlert = new();

    public AlertRules Rules { get; } = rules;

    public List<Alert> Process(IEnumerable<AccessRecord> records)
    {
        var alerts = new List<Alert>();
        foreach (var r in records)
        {
            // A refused attempt counts only towards the denied threshold (files and folders alike)
            if (r.Denied)
            {
                CountBurst(r, "Denied", Rules.DeniedThreshold, alerts);
                continue;
            }
            // a folder deletion follows the deletion of its contents, which is already counted
            if (r.IsFolder) continue;

            if (Rules.Ransomware is { Enabled: true } ransomware)
                ObserveRansomware(r, ransomware, alerts);

            // Creating a file is writing it
            var type = r.AccessType == AccessTypes.Create ? AccessTypes.Write : r.AccessType;
            var threshold = type switch
            {
                "Delete" => Rules.DeleteThreshold,
                "Write" => Rules.WriteThreshold,
                "Read" => Rules.ReadThreshold,
                _ => 0,
            };
            CountBurst(r, type, threshold, alerts);
        }
        return alerts;
    }

    private void CountBurst(AccessRecord r, string type, int threshold, List<Alert> alerts)
    {
        if (threshold <= 0) return;

        var key = (r.UserName, type);
        if (!_windows.TryGetValue(key, out var window))
            _windows[key] = window = new Queue<AccessRecord>();

        window.Enqueue(r);
        var windowStart = r.AccessTime.AddMinutes(-Rules.WindowMinutes);
        while (window.Count > 0 && (window.Peek().AccessTime < windowStart || window.Count > threshold))
            window.Dequeue();

        if (window.Count < threshold) return;
        if (_lastAlert.TryGetValue(key, out var last) && r.AccessTime < last.AddMinutes(Rules.CooldownMinutes))
            return;

        _lastAlert[key] = r.AccessTime;
        alerts.Add(BuildAlert(type, window.ToList()));
        window.Clear();
    }

    private Alert BuildAlert(string type, List<AccessRecord> items, string rule = "", string? detail = null, int? count = null,
        int? windowMinutes = null, string priority = "Normal")
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
        var servers = string.Join(", ", items.Select(i => i.ServerName).Where(s => s.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase));

        return new Alert(type, first.UserName, count ?? items.Count, windowMinutes ?? Rules.WindowMinutes,
            first.AccessTime, latest.AccessTime, latest.ClientIp, latest.ClientMachine, topFolders, samples, servers,
            rule, detail, priority);
    }

    // ---- ransomware-like behaviour ----

    // What one user did on one server within the window. Counters follow the queue, so a record
    // costs O(1); the queue is capped so a very busy user cannot use unbounded memory.
    private sealed class RansomwareWindow
    {
        public readonly Queue<RwEntry> Entries = new();
        public int Writes, Renames;
        public readonly Dictionary<string, int> NewExtensions = new(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string, int> NoteFolders = new(StringComparer.OrdinalIgnoreCase);
    }

    private readonly record struct RwEntry(AccessRecord Record, bool IsRename, string? NewExtension, string? NoteFolder);

    private const int MaxWindowEntries = 20_000;

    private void ObserveRansomware(AccessRecord r, RansomwareRules rules, List<Alert> alerts)
    {
        bool isRename = r.AccessType == AccessTypes.Rename;
        bool isWrite = r.AccessType is AccessTypes.Write or AccessTypes.Create;
        if (!isRename && !isWrite) return;

        string? newExt = null, noteFolder = null;
        if (isRename && r.NewPath != null)
        {
            var oldExt = ExtensionOf(r.FilePath);
            var ext = ExtensionOf(r.NewPath);
            if (ext.Length > 0 && !ext.Equals(oldExt, StringComparison.OrdinalIgnoreCase) && !IsBenignRename(oldExt, ext))
                newExt = ext;
        }
        else if (isWrite && IsRansomNote(r.FileName))
            noteFolder = r.FolderPath;

        var key = (r.ServerName, r.UserName);
        if (!_ransomware.TryGetValue(key, out var w))
            _ransomware[key] = w = new RansomwareWindow();

        w.Entries.Enqueue(new RwEntry(r, isRename, newExt, noteFolder));
        if (isRename) w.Renames++; else w.Writes++;
        if (newExt != null) w.NewExtensions[newExt] = w.NewExtensions.GetValueOrDefault(newExt) + 1;
        if (noteFolder != null) w.NoteFolders[noteFolder] = w.NoteFolders.GetValueOrDefault(noteFolder) + 1;

        var windowStart = r.AccessTime.AddMinutes(-rules.WindowMinutes);
        while (w.Entries.Count > 0 && (w.Entries.Peek().Record.AccessTime < windowStart || w.Entries.Count > MaxWindowEntries))
            Remove(w, w.Entries.Dequeue());

        // extension: many renames to the same new extension
        foreach (var (ext, count) in w.NewExtensions)
        {
            if (count < rules.SameExtensionRenames) continue;
            if (!CooledDown(key, "extension", r.AccessTime, rules)) break;
            var items = w.Entries.Where(e => e.NewExtension != null && ext.Equals(e.NewExtension, StringComparison.OrdinalIgnoreCase))
                .Select(e => e.Record).ToList();
            alerts.Add(BuildRansomware(items, "extension", $".{ext} ({count} files)", count, rules));
            break;
        }

        // burst: lots of writing together with lots of renaming
        if (w.Writes >= rules.BurstWrites && w.Renames >= rules.BurstRenames && CooledDown(key, "burst", r.AccessTime, rules))
            alerts.Add(BuildRansomware(w.Entries.Select(e => e.Record).ToList(), "burst",
                $"{w.Writes} writes, {w.Renames} renames", w.Writes + w.Renames, rules));

        // note: a ransom note dropped into several folders
        if (w.NoteFolders.Count >= rules.NoteFolders && CooledDown(key, "note", r.AccessTime, rules))
        {
            var items = w.Entries.Where(e => e.NoteFolder != null).Select(e => e.Record).ToList();
            alerts.Add(BuildRansomware(items, "note",
                $"{string.Join(", ", items.Select(i => i.FileName).Distinct(StringComparer.OrdinalIgnoreCase).Take(3))} ({w.NoteFolders.Count} folders)",
                items.Count, rules));
        }
    }

    private static void Remove(RansomwareWindow w, RwEntry e)
    {
        if (e.IsRename) w.Renames--; else w.Writes--;
        if (e.NewExtension != null && --w.NewExtensions[e.NewExtension] <= 0) w.NewExtensions.Remove(e.NewExtension);
        if (e.NoteFolder != null && --w.NoteFolders[e.NoteFolder] <= 0) w.NoteFolders.Remove(e.NoteFolder);
    }

    // Per (server, user, rule); true and remembered when an alert may be sent now
    private bool CooledDown((string Server, string User) key, string rule, DateTime now, RansomwareRules rules)
    {
        var k = (key.Server, key.User, rule);
        if (_lastRansomwareAlert.TryGetValue(k, out var last) && now < last.AddMinutes(rules.CooldownMinutes))
            return false;
        _lastRansomwareAlert[k] = now;
        return true;
    }

    private Alert BuildRansomware(List<AccessRecord> items, string rule, string detail, int count, RansomwareRules rules) =>
        BuildAlert("Ransomware", items, rule, detail, count, rules.WindowMinutes, "High");

    private static string ExtensionOf(string path)
    {
        var name = path[(path.LastIndexOfAny(['\\', '/']) + 1)..];
        var dot = name.LastIndexOf('.');
        return dot <= 0 || dot == name.Length - 1 ? "" : name[(dot + 1)..];
    }

    // Renames to these are what applications and people do every day
    private static readonly HashSet<string> TempExtensions = new(StringComparer.OrdinalIgnoreCase)
        { "tmp", "temp", "bak", "old", "part", "crdownload", "partial", "swp", "orig" };

    // Document types, with the older extensions they replace
    private static readonly Dictionary<string, string[]> DocumentFamilies = new(StringComparer.OrdinalIgnoreCase)
    {
        ["docx"] = ["doc"], ["xlsx"] = ["xls"], ["pptx"] = ["ppt"], ["pdf"] = [], ["jpg"] = ["jpeg"], ["png"] = [],
        ["txt"] = [], ["zip"] = [],
    };

    internal static bool IsBenignRename(string oldExt, string newExt)
    {
        if (newExt.StartsWith('~') || TempExtensions.Contains(newExt)) return true;
        if (!DocumentFamilies.TryGetValue(newExt, out var older)) return false;
        // a temporary file saved as the document, or a document saved in its newer format
        return oldExt.Length == 0 || oldExt.StartsWith('~') || TempExtensions.Contains(oldExt)
            || older.Contains(oldExt, StringComparer.OrdinalIgnoreCase);
    }

    private static readonly HashSet<string> NoteExtensions = new(StringComparer.OrdinalIgnoreCase)
        { "txt", "html", "htm", "hta", "url", "rtf" };

    // File names (without extension) that ransom notes are known by
    internal static readonly Regex[] RansomwareNotes = new[]
    {
        @"^(readme|read[_ -]?me)[_ -]*(to[_ -]*)?(decrypt|restore|recover)",
        @"^(how[_ -]*to[_ -]*)?(decrypt|recover|restore)[_ -]*(your[_ -]*)?(files?|data|instructions?)",
        @"^(decrypt|restore|recover)[_ -]*(files?|instructions?|my[_ -]*files)",
        @"^!+.*(decrypt|recover|readme|help)",
        @"^(_readme_?|readme_)$",
        @"^@?please[_ -]?read[_ -]?me@?",
        @"^\+?(help|hel)[_ -]*(decrypt|recover|restore)",
        @"^ryukreadme",
        @"^#?(decrypt|recover)#?(?![a-z])",
        @"-decrypt$",
        @"\.readme$",
        @"how[_ -]?to[_ -]?back[_ -]?files",
    }.Select(p => new Regex(p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled)).ToArray();

    internal static bool IsRansomNote(string fileName)
    {
        var dot = fileName.LastIndexOf('.');
        if (dot <= 0 || !NoteExtensions.Contains(fileName[(dot + 1)..])) return false;
        var name = fileName[..dot];
        return RansomwareNotes.Any(rx => rx.IsMatch(name));
    }
}
