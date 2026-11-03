using System.Text.Json.Nodes;

namespace FileAccessMonitor.Services;

// The "permissions" agent job: read the permissions below a monitored folder. Shared by the
// server, the Windows agent and the Linux agent (linked into the Linux agent project, so no
// Windows-only or server-only code here).
//
// The result is compact: arrays instead of objects, and a table of principals that rows point into.
//   { exists, os, root, scannedAt, folders, files, truncated, limit, elapsedMs, errors[],
//     principals: [[name, sid|null], ...], shares: [{name, path, guestOk, readOnly, validUsers, writeList, ntAcl}],
//     rows: [[relPath, flags, ownerIdx, [[principalIdx, kind, level, scope(, levelBeforeMask)], ...]], ...] }
public static class PermissionContract
{
    public const string JobType = "permissions";

    // Level bits of an entry
    public const int Read = 1, Write = 2, Delete = 4, Perm = 8, Exec = 16;

    // Row flags
    public const int FlagFolder = 1, FlagInheritanceBroken = 2, FlagNotReadable = 4, FlagExplicit = 8,
        FlagAcl = 16, FlagDefaultAcl = 32, FlagOwnerDiffers = 64;

    // Entry scope bits (where an entry applies)
    public const int ScopeThis = 1, ScopeSubfolders = 2, ScopeFiles = 4;

    // Hard maxima; the agent clamps what the server asks for
    public const int MaxFoldersLimit = 20_000, MaxFilesLimit = 200_000, MaxDepthLimit = 32, TimeLimitMax = 900;
    public const int MaxErrors = 100, MaxRows = 20_000;

    public static PermissionScanOptions Clamp(PermissionScanOptions o) => o with
    {
        MaxFolders = Math.Clamp(o.MaxFolders, 1, MaxFoldersLimit),
        MaxFiles = Math.Clamp(o.MaxFiles, 0, MaxFilesLimit),
        MaxDepth = Math.Clamp(o.MaxDepth, 0, MaxDepthLimit),
        TimeLimitSeconds = Math.Clamp(o.TimeLimitSeconds, 5, TimeLimitMax),
    };

    // Job arguments: { path, maxFolders, maxFiles, maxDepth, includeFiles, timeLimitSeconds }
    public static JsonObject ToArgs(string path, PermissionScanOptions o) => new()
    {
        ["path"] = path, ["maxFolders"] = o.MaxFolders, ["maxFiles"] = o.MaxFiles, ["maxDepth"] = o.MaxDepth,
        ["includeFiles"] = o.IncludeFiles, ["timeLimitSeconds"] = o.TimeLimitSeconds,
    };

    public static PermissionScanOptions OptionsFrom(JsonObject args)
    {
        var d = new PermissionScanOptions();
        return Clamp(new PermissionScanOptions(
            Int(args, "maxFolders", d.MaxFolders), Int(args, "maxFiles", d.MaxFiles), Int(args, "maxDepth", d.MaxDepth),
            args["includeFiles"] is JsonValue v && v.TryGetValue<bool>(out var b) ? b : d.IncludeFiles,
            Int(args, "timeLimitSeconds", d.TimeLimitSeconds)));
    }

    private static int Int(JsonObject args, string name, int fallback) =>
        args[name] is JsonValue v && v.TryGetValue<int>(out var i) ? i : fallback;

    // Name of a level: full, modify, readWrite, write, read, list, traverse, special
    public static string LevelCode(int level)
    {
        var rights = level & (Read | Write | Delete | Perm);
        return rights switch
        {
            Read | Write | Delete | Perm => "full",
            Read | Write | Delete => "modify",
            Read | Write => "readWrite",
            Write => "write",
            Read => (level & Exec) != 0 ? "read" : "list",
            0 when (level & Exec) != 0 => "traverse",
            _ => "special",
        };
    }

    // English text of a level: Full, Modify, Read/Write, Write, Read, List/Read data, Traverse, Special (0x..)
    public static string LevelLabel(int level) => LevelCode(level) switch
    {
        "full" => "Full",
        "modify" => "Modify",
        "readWrite" => "Read/Write",
        "write" => "Write",
        "read" => "Read",
        "list" => "List/Read data",
        "traverse" => "Traverse",
        _ => $"Special (0x{level:X})",
    };

    // English text of a scope (bits 1 this folder, 2 subfolders, 4 files)
    public static string ScopeLabel(int scope) => (scope & 7) switch
    {
        1 => "This folder only",
        2 => "Subfolders only",
        3 => "This folder and subfolders",
        4 => "Files only",
        5 => "This folder and files",
        6 => "Subfolders and files",
        7 => "This folder, subfolders and files",
        _ => "",
    };

    // The path of a row below the root, written with the root's own separator
    public static string Absolute(string root, string rel)
    {
        if (rel.Length == 0) return root;
        var sep = root.StartsWith('/') ? '/' : '\\';
        return root.TrimEnd(sep) + sep + rel;
    }

    // The answer to an agent that has no such path
    public static JsonObject NotFound() => new() { ["exists"] = false };
}

public record PermissionScanOptions(int MaxFolders = 5000, int MaxFiles = 50000, int MaxDepth = 8,
    bool IncludeFiles = true, int TimeLimitSeconds = 300);

// One entry of a row: who (index into the principal table), allow (0) or deny (1), what (level bits),
// where it applies (scope bits), and for a Linux entry limited by the ACL mask the level before the mask
public readonly record struct PermissionAce(int Principal, int Kind, int Level, int Scope, int? LevelBeforeMask = null);

// Builds the result of a scan; Windows, Linux and the tests share it. Not thread safe.
public sealed class PermissionResultBuilder
{
    private readonly string _os, _root;
    private readonly PermissionScanOptions _options;
    private readonly List<(string Name, string? Sid)> _principals = [];
    private readonly Dictionary<string, int> _index = new(StringComparer.Ordinal);
    private readonly JsonArray _rows = [];
    private readonly List<string> _errors = [];
    private JsonArray _shares = [];
    private readonly DateTime _started = DateTime.UtcNow;

    public int Folders { get; private set; }
    public int Files { get; private set; }
    public bool Truncated { get; private set; }
    public string? Limit { get; private set; }
    public int Rows => _rows.Count;

    public PermissionResultBuilder(string os, string root, PermissionScanOptions options)
    {
        _os = os;
        _root = root;
        _options = options;
    }

    // Index of the principal in the table (added on first use)
    public int Principal(string name, string? sid)
    {
        var key = sid ?? "n:" + name;
        if (_index.TryGetValue(key, out var i)) return i;
        _principals.Add((name, sid));
        return _index[key] = _principals.Count - 1;
    }

    // Counts a folder or file that was looked at, listed or not
    public void CountFolder() => Folders++;
    public void CountFile() => Files++;

    public void AddRow(string rel, int flags, int ownerIdx, IEnumerable<PermissionAce> aces)
    {
        var list = new JsonArray();
        foreach (var a in aces)
        {
            var ace = new JsonArray(a.Principal, a.Kind, a.Level, a.Scope);
            if (a.LevelBeforeMask is { } before && before != a.Level) ace.Add(before);
            list.Add(ace);
        }
        if (_rows.Count >= PermissionContract.MaxRows) { Truncate("rows"); return; }
        _rows.Add(new JsonArray(rel, flags, ownerIdx, list));
    }

    public void AddError(string message)
    {
        if (_errors.Count < PermissionContract.MaxErrors) _errors.Add(message);
    }

    // The first limit reached is the one reported
    public void Truncate(string limit)
    {
        if (Truncated) return;
        Truncated = true;
        Limit = limit;
    }

    public void SetShares(JsonArray shares) => _shares = shares;

    public JsonObject Build()
    {
        var result = new JsonObject
        {
            ["exists"] = true, ["os"] = _os, ["root"] = _root,
            ["scannedAt"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["folders"] = Folders, ["files"] = Files, ["truncated"] = Truncated, ["limit"] = Limit,
            ["elapsedMs"] = (long)(DateTime.UtcNow - _started).TotalMilliseconds,
            ["errors"] = new JsonArray(_errors.Select(e => (JsonNode)JsonValue.Create(e)!).ToArray()),
            ["principals"] = new JsonArray(_principals
                .Select(p => (JsonNode)new JsonArray(p.Name, p.Sid)).ToArray()),
            ["rows"] = _rows,
        };
        if (_os == "linux") result["shares"] = _shares;
        return result;
    }
}
