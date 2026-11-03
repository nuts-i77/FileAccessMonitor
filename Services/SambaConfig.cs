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
    public void EnableAudit(string share, bool samba414)
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
        var ops = samba414 ? "create_file renameat unlinkat" : "create_file rename unlink rmdir";
        _lines.InsertRange(start + 1,
        [
            Begin,
            $"\tvfs objects = {string.Join(' ', modules)}",
            $"\tfull_audit:prefix = {Prefix}",
            $"\tfull_audit:success = {ops}",
            "\tfull_audit:failure = none",
            "\tfull_audit:facility = local5",
            "\tfull_audit:priority = notice",
            "\tfull_audit:syslog = true",
            End,
        ]);
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
