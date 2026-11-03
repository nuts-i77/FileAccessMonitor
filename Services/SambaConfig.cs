using System.Text.RegularExpressions;

namespace FileAccessMonitor.Services;

// Turns Samba's full_audit module on and off for shares, by editing smb.conf. The lines the agent
// adds are kept between marker comments, and lines it replaces (an existing "vfs objects" or
// full_audit setting) are commented out with a marker, so turning auditing off restores the share
// exactly as it was.
public class SambaConfigText
{
    public const string Begin = "# FileAccessMonitor begin: file access auditing (removed when the folder is no longer monitored)";
    public const string End = "# FileAccessMonitor end";
    public const string DisabledPrefix = "# FileAccessMonitor replaced: ";
    public const string Prefix = "%u|%I|%m|%S|%P";

    private static readonly Regex SectionLine = new(@"^\s*\[([^\]]+)\]\s*$");
    private static readonly Regex ParamLine = new(@"^\s*([^=#;\[]+?)\s*=\s*(.*?)\s*$");

    private readonly List<string> _lines;

    public SambaConfigText(string text) =>
        _lines = text.Replace("\r\n", "\n").Split('\n').ToList();

    public override string ToString() => string.Join("\n", _lines);

    // Share name -> path, for sections defined in this file (not [global], [homes] or printers)
    public Dictionary<string, string> Shares()
    {
        var shares = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, start, end) in Sections())
        {
            if (IsSpecial(name)) continue;
            var path = Value(start, end, "path") ?? Value(start, end, "directory");
            if (!string.IsNullOrEmpty(path)) shares[name] = path;
        }
        return shares;
    }

    public bool IsAudited(string share) =>
        Sections().FirstOrDefault(s => s.Name.Equals(share, StringComparison.OrdinalIgnoreCase)) is { Name: not null } s
        && Enumerable.Range(s.Start, s.End - s.Start).Any(i => _lines[i].Trim() == Begin);

    // Adds the audit settings to a share. samba414: Samba 4.14 or later names the operations *at.
    public void EnableAudit(string share, bool samba414, AuditOptions? options = null)
    {
        DisableAudit(share); // start from the share as configured by its owner
        var (_, start, end) = Find(share);

        // A share's own "vfs objects" replaces the global one, so keep the modules that apply now
        var objects = Value(start, end, "vfs objects") ?? Value(start, end, "vfs object")
                      ?? GlobalValue("vfs objects") ?? GlobalValue("vfs object") ?? "";
        var modules = objects.Split([' ', ',', '\t'], StringSplitOptions.RemoveEmptyEntries).ToList();
        if (!modules.Contains("full_audit")) modules.Add("full_audit");

        for (var i = start + 1; i < end; i++)
        {
            if (ParamLine.Match(_lines[i]) is { Success: true } m && !_lines[i].TrimStart().StartsWith('#')
                && (IsKey(m, "vfs objects") || IsKey(m, "vfs object") || Key(m).StartsWith("full_audit:")))
                _lines[i] = DisabledPrefix + _lines[i];
        }
        var (successOps, failureOps) = AuditOps(samba414, options ?? AuditOptions.Default);
        _lines.InsertRange(start + 1,
        [
            Begin,
            $"\tvfs objects = {string.Join(' ', modules)}",
            $"\tfull_audit:prefix = {Prefix}",
            $"\tfull_audit:success = {successOps}",
            $"\tfull_audit:failure = {failureOps}",
            "\tfull_audit:facility = local5",
            "\tfull_audit:priority = notice",
            "\tfull_audit:syslog = true",
            End,
        ]);
    }

    // The operations to log. Success: what happened (create_file also tells how a file was opened,
    // and fset_nt_acl is a permission change). Failure: refused accesses, when asked for; the
    // parser keeps only EACCES / EPERM. An operation the installed full_audit module does not know
    // makes smbd log everything ("Could not find opname"), so with the module's op names known,
    // others are left out.
    internal static (string Success, string Failure) AuditOps(bool samba414, AuditOptions options)
    {
        var success = samba414 ? new List<string> { "create_file", "renameat", "unlinkat" } : ["create_file", "rename", "unlink", "rmdir"];
        success.Add("fset_nt_acl");
        var failure = options.RecordDenied
            ? (samba414 ? new List<string> { "create_file", "unlinkat", "renameat" } : ["create_file", "unlink", "rename", "rmdir"])
            : [];
        // Without the module's op list only the operations Samba has always had are used
        if (options.AvailableOps == null) success.Remove("fset_nt_acl");
        else
        {
            success.RemoveAll(o => !options.AvailableOps.Contains(o));
            failure.RemoveAll(o => !options.AvailableOps.Contains(o));
        }
        return (string.Join(' ', success), failure.Count == 0 ? "none" : string.Join(' ', failure));
    }

    public void DisableAudit(string share)
    {
        var (_, start, end) = Find(share);
        var kept = new List<string>();
        var inBlock = false;
        for (var i = start + 1; i < end; i++)
        {
            var trimmed = _lines[i].Trim();
            if (trimmed == Begin) { inBlock = true; continue; }
            if (trimmed == End) { inBlock = false; continue; }
            if (inBlock) continue;
            kept.Add(_lines[i].StartsWith(DisabledPrefix) ? _lines[i][DisabledPrefix.Length..] : _lines[i]);
        }
        _lines.RemoveRange(start + 1, end - start - 1);
        _lines.InsertRange(start + 1, kept);
    }

    private (string Name, int Start, int End) Find(string share) =>
        Sections().FirstOrDefault(s => s.Name.Equals(share, StringComparison.OrdinalIgnoreCase)) is { Name: not null } s
            ? s
            : throw new InvalidOperationException($"The share [{share}] is not defined in smb.conf.");

    // (name, header line, line after the section)
    private List<(string Name, int Start, int End)> Sections()
    {
        var result = new List<(string, int, int)>();
        string? name = null;
        var start = -1;
        for (var i = 0; i < _lines.Count; i++)
        {
            if (SectionLine.Match(_lines[i]) is not { Success: true } m) continue;
            if (name != null) result.Add((name, start, i));
            name = m.Groups[1].Value.Trim();
            start = i;
        }
        if (name != null) result.Add((name, start, _lines.Count));
        return result;
    }

    private string? Value(int start, int end, string key)
    {
        string? value = null; // the last assignment wins
        for (var i = start + 1; i < end; i++)
        {
            var line = _lines[i].TrimStart();
            if (line.StartsWith('#') || line.StartsWith(';')) continue;
            if (ParamLine.Match(_lines[i]) is { Success: true } m && IsKey(m, key)) value = m.Groups[2].Value;
        }
        return value;
    }

    private string? GlobalValue(string key) =>
        Sections().FirstOrDefault(s => s.Name.Equals("global", StringComparison.OrdinalIgnoreCase)) is { Name: not null } g
            ? Value(g.Start, g.End, key)
            : null;

    private static string Key(Match m) => Regex.Replace(m.Groups[1].Value.Trim().ToLowerInvariant(), @"\s+", " ");

    private static bool IsKey(Match m, string key) => Key(m) == key;

    private static bool IsSpecial(string name) =>
        name.Equals("global", StringComparison.OrdinalIgnoreCase) || name.Equals("homes", StringComparison.OrdinalIgnoreCase)
        || name.Equals("printers", StringComparison.OrdinalIgnoreCase) || name.Equals("print$", StringComparison.OrdinalIgnoreCase);
}

// What to log besides the basics. RecordDenied: refused accesses (the failure list).
// AvailableOps: the operation names the installed full_audit module knows (null = not known).
public record AuditOptions(bool RecordDenied, IReadOnlySet<string>? AvailableOps)
{
    public static readonly AuditOptions Default = new(false, null);
}

// The operation names of the installed full_audit module, read from the module file: its table of
// names is plain NUL-delimited text.
public static class SambaOps
{
    private static readonly Regex OpName = new(@"^[a-z][a-z0-9_]{2,40}$");

    // Where the module usually is, when smbd does not say ("smbd -b": MODULESDIR)
    private static readonly string[] Fallbacks =
    [
        "/usr/lib64/samba/vfs/full_audit.so",                  // Rocky, RHEL, Alma, Fedora
        "/usr/lib/x86_64-linux-gnu/samba/vfs/full_audit.so",   // Debian, Ubuntu
        "/usr/lib/aarch64-linux-gnu/samba/vfs/full_audit.so",
        "/usr/lib/samba/vfs/full_audit.so",
    ];

    public static IReadOnlySet<string>? Available()
    {
        try
        {
            var modules = Regex.Match(Samba.Run("smbd", "-b").Output, @"MODULESDIR:\s*(\S+)") is { Success: true } m
                ? Path.Combine(m.Groups[1].Value, "vfs", "full_audit.so") : null;
            var file = new[] { modules }.Concat(Fallbacks).FirstOrDefault(f => f != null && File.Exists(f));
            return file == null ? null : Available(File.ReadAllBytes(file));
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    // Every NUL-delimited lower-case identifier in the module; null when there are none (not a module)
    public static IReadOnlySet<string>? Available(byte[] module)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        var start = 0;
        for (var i = 0; i <= module.Length; i++)
        {
            if (i < module.Length && module[i] != 0) continue;
            if (i - start is >= 3 and <= 41)
            {
                var text = System.Text.Encoding.ASCII.GetString(module, start, i - start);
                if (OpName.IsMatch(text)) names.Add(text);
            }
            start = i + 1;
        }
        return names.Count == 0 ? null : names;
    }
}
