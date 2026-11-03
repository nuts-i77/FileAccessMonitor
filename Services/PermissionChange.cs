using System.Collections.Concurrent;
using System.Security.AccessControl;
using System.Security.Principal;

namespace FileAccessMonitor.Services;

// Turns the old and new security descriptor of event 4670 into the short text stored in
// AccessRecord.Detail. Pure function apart from SID lookups, which can be replaced for tests.
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public static class PermissionChange
{
    public const int MaxLength = 2000;

    // What changed, and whether the object's own (non-inherited) entries, owner or inheritance
    // setting are part of it. A change that is only inherited from the parent is reported once on
    // the parent, so the children's events can be dropped (see PermissionMerger).
    public sealed record Result(string Text, bool Explicit);

    private const AceFlags PropagationMask =
        AceFlags.ContainerInherit | AceFlags.ObjectInherit | AceFlags.NoPropagateInherit | AceFlags.InheritOnly;

    private static readonly ConcurrentDictionary<string, string> NameCache = new();

    // null = nothing changed (identical descriptors); otherwise the text, at most MaxLength characters
    public static string? Describe(string? oldSddl, string? newSddl, Func<SecurityIdentifier, string>? resolve = null) =>
        Analyze(oldSddl, newSddl, resolve)?.Text;

    public static Result? Analyze(string? oldSddl, string? newSddl, Func<SecurityIdentifier, string>? resolve = null)
    {
        resolve ??= DefaultResolve;
        if (string.Equals(oldSddl, newSddl, StringComparison.Ordinal)) return null;

        var newSd = TryParse(newSddl);
        // Without a readable new descriptor there is nothing to compare; the event still says a change happened
        if (newSd == null) return string.IsNullOrWhiteSpace(newSddl) ? null : new Result("permissions changed", true);
        var oldSd = TryParse(oldSddl);
        if (oldSd == null) return new Result("permissions changed", true);

        var lines = new List<string>();

        if (oldSd.Owner != null && newSd.Owner != null && oldSd.Owner != newSd.Owner)
            lines.Add($"owner: {resolve(oldSd.Owner)} -> {resolve(newSd.Owner)}");

        var oldAces = Aces(oldSd);
        var newAces = Aces(newSd);
        var removed = Subtract(oldAces, newAces);
        var added = Subtract(newAces, oldAces);
        foreach (var a in removed.Where(a => !a.Inherited)) lines.Add("- " + Format(a, resolve));
        foreach (var a in added.Where(a => !a.Inherited)) lines.Add("+ " + Format(a, resolve));

        var oldProtected = (oldSd.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0;
        var newProtected = (newSd.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0;
        if (oldProtected != newProtected) lines.Add("inheritance: " + (newProtected ? "disabled" : "enabled"));

        var isExplicit = lines.Count > 0;
        if (!isExplicit)
        {
            // Only inherited entries differ (or only flags that do not change who may do what)
            if (removed.Count == 0 && added.Count == 0) return null;
            lines.Add("inherited permissions changed");
        }
        return new Result(Truncate(string.Join("\n", lines)), isExplicit);
    }

    private sealed record Ace(bool Allow, SecurityIdentifier Sid, int Mask, AceFlags Propagation, bool Inherited);

    private static RawSecurityDescriptor? TryParse(string? sddl)
    {
        if (string.IsNullOrWhiteSpace(sddl)) return null;
        try { return new RawSecurityDescriptor(sddl); }
        catch (ArgumentException) { return null; }
    }

    private static List<Ace> Aces(RawSecurityDescriptor sd)
    {
        var list = new List<Ace>();
        if (sd.DiscretionaryAcl == null) return list;
        foreach (var ace in sd.DiscretionaryAcl)
        {
            if (ace is not KnownAce known) continue;
            bool allow;
            switch (known.AceType)
            {
                case AceType.AccessAllowed or AceType.AccessAllowedObject or AceType.AccessAllowedCallback
                    or AceType.AccessAllowedCallbackObject: allow = true; break;
                case AceType.AccessDenied or AceType.AccessDeniedObject or AceType.AccessDeniedCallback
                    or AceType.AccessDeniedCallbackObject: allow = false; break;
                default: continue;
            }
            list.Add(new Ace(allow, known.SecurityIdentifier, known.AccessMask, known.AceFlags & PropagationMask,
                (known.AceFlags & AceFlags.Inherited) != 0));
        }
        return list;
    }

    // Multiset difference: entries of a that b does not have (an entry that occurs twice in a and once in b is left once)
    private static List<Ace> Subtract(List<Ace> a, List<Ace> b)
    {
        var rest = new List<Ace>(b);
        var result = new List<Ace>();
        foreach (var ace in a)
        {
            var i = rest.FindIndex(x => x == ace);
            if (i >= 0) rest.RemoveAt(i);
            else result.Add(ace);
        }
        return result;
    }

    private static string Format(Ace a, Func<SecurityIdentifier, string> resolve)
    {
        var text = $"{(a.Allow ? "allow" : "deny")} {resolve(a.Sid)}: {RightsName(a.Mask)}";
        var scope = Scope(a.Propagation);
        return scope.Length == 0 ? text : text + " " + scope;
    }

    internal static string RightsName(int mask) => mask switch
    {
        0x1F01FF => "FullControl",
        0x1301BF => "Modify",
        0x1200A9 => "ReadAndExecute",
        0x120089 => "Read",
        0x100116 => "Write",
        _ => $"0x{mask:X}",
    };

    // No suffix for the two common cases: nothing set (a file entry) and "this folder, subfolders and files"
    internal static string Scope(AceFlags f)
    {
        var container = (f & AceFlags.ContainerInherit) != 0;
        var obj = (f & AceFlags.ObjectInherit) != 0;
        var inheritOnly = (f & AceFlags.InheritOnly) != 0;
        var noPropagate = (f & AceFlags.NoPropagateInherit) != 0;
        if (!container && !obj) return "";

        string text;
        if (container && obj) text = inheritOnly ? "subfolders and files only" : "";
        else if (container) text = inheritOnly ? "subfolders only" : "this folder and subfolders";
        else text = inheritOnly ? "files only" : "this folder and files";
        if (noPropagate) text = text.Length == 0 ? "one level only" : text + ", one level only";
        return text.Length == 0 ? "" : $"({text})";
    }

    private static string Truncate(string text) =>
        text.Length <= MaxLength ? text : text[..(MaxLength - 3)] + "...";

    private static string DefaultResolve(SecurityIdentifier sid)
    {
        if (NameCache.Count > 5000) NameCache.Clear();
        return NameCache.GetOrAdd(sid.Value, _ =>
        {
            try
            {
                return sid.Translate(typeof(NTAccount)).Value;
            }
            catch (SystemException) // not mapped, or the domain controller cannot be reached
            {
                return sid.Value;
            }
        });
    }
}

// Several 4670 events for one change are recorded once. Changing the permissions of a folder with
// inheritance makes Windows log one event per child; their text only says that inherited entries
// changed, which the folder's own record already tells.
public class PermissionMerger
{
    public static readonly TimeSpan SamePathWindow = TimeSpan.FromSeconds(2);
    public static readonly TimeSpan ParentWindow = TimeSpan.FromSeconds(10);
    private const int MaxEntries = 50_000;

    private readonly Dictionary<(string Logon, string Path), DateTime> _recorded = new();

    // logonId: the user's session (a user logged on twice has two); isExplicit: the change is not just inherited
    public bool ShouldRecord(string logonId, string path, DateTime time, bool isExplicit)
    {
        var key = (logonId, path.ToUpperInvariant());
        if (_recorded.TryGetValue(key, out var same) && (time - same).Duration() < SamePathWindow)
            return false;

        if (!isExplicit)
        {
            for (var parent = ParentOf(key.Item2); parent != null; parent = ParentOf(parent))
                if (_recorded.TryGetValue((logonId, parent), out var t) && time >= t && time - t < ParentWindow)
                    return false;
        }

        if (_recorded.Count >= MaxEntries)
            foreach (var old in _recorded.Where(kv => time - kv.Value > ParentWindow).Select(kv => kv.Key).ToList())
                _recorded.Remove(old);
        if (_recorded.Count >= MaxEntries) _recorded.Clear();
        _recorded[key] = time;
        return true;
    }

    private static string? ParentOf(string path)
    {
        var i = path.LastIndexOf('\\');
        return i > 2 ? path[..i] : null; // stops above "C:\"
    }
}
