using System.Text.RegularExpressions;

namespace FileAccessMonitor.Services;

// Which entries give broad access, and how serious that is. Server side only, so the rules can
// improve without updating agents. Windows principals are classified by SID, never by name: names
// are localized.
public static class PermissionAnalysis
{
    public const string High = "high", Medium = "medium";

    private static readonly Dictionary<string, string> WellKnownSids = new()
    {
        ["S-1-1-0"] = "everyone",
        ["S-1-5-11"] = "authenticatedUsers",
        ["S-1-5-32-545"] = "users",
        ["S-1-5-32-546"] = "guests",
        ["S-1-5-7"] = "anonymous",
        ["S-1-5-2"] = "network",
        ["S-1-5-4"] = "interactive",
    };

    // Domain Users, Domain Guests and Domain Computers: S-1-5-21-<domain>-513 / 514 / 515
    private static readonly Regex DomainSid = new(@"^S-1-5-21-\d+-\d+-\d+-(513|514|515)$", RegexOptions.Compiled);

    // Linux groups that mean "everybody" on a typical file server
    private static readonly string[] BroadGroups = ["users", "everyone", "domain users", "nogroup", "nobody", "guests", "domain guests"];

    // The kind of broad access a principal stands for (everyone, authenticatedUsers, users, guests,
    // anonymous, network, interactive, domainUsers, domainGuests, domainComputers, other, group), or null.
    // Linux principals have no SID: "other", "group:users", "user:taro".
    // extra: more names from settings.json (Permissions:BroadPrincipals), compared case-insensitively
    public static string? BroadKind(string principal, string? sid, IReadOnlyCollection<string>? extra = null)
    {
        if (sid != null)
        {
            if (WellKnownSids.TryGetValue(sid, out var kind)) return kind;
            if (DomainSid.Match(sid) is { Success: true } m)
                return m.Groups[1].Value switch { "513" => "domainUsers", "514" => "domainGuests", _ => "domainComputers" };
        }
        else
        {
            if (principal == "other") return "other";
            if (principal.StartsWith("group:", StringComparison.Ordinal))
            {
                var group = principal[6..];
                var bare = group[(group.LastIndexOfAny(['\\', '/']) + 1)..];
                if (BroadGroups.Any(g => g.Equals(group, StringComparison.OrdinalIgnoreCase) || g.Equals(bare, StringComparison.OrdinalIgnoreCase)))
                    return "group";
            }
        }
        if (extra != null && extra.Count > 0)
        {
            var bare = principal[(principal.LastIndexOfAny(['\\', ':']) + 1)..];
            if (extra.Any(e => e.Equals(principal, StringComparison.OrdinalIgnoreCase) || e.Equals(bare, StringComparison.OrdinalIgnoreCase)))
                return "custom";
        }
        return null;
    }

    // high: a broad principal may write, delete or change permissions; medium: it may read.
    // null: not flagged (a deny entry, or only traversal).
    public static string? Severity(string? broadKind, int level, bool deny)
    {
        if (broadKind == null || deny) return null;
        if ((level & (PermissionContract.Write | PermissionContract.Delete | PermissionContract.Perm)) != 0) return High;
        return (level & PermissionContract.Read) != 0 ? Medium : null;
    }

    // A Samba share that allows guests: high when it is writable, otherwise medium
    public static string? ShareSeverity(bool guestOk, bool readOnly) => !guestOk ? null : readOnly ? Medium : High;

    public static string MaxSeverity(string? a, string? b) => (a, b) switch
    {
        (High, _) or (_, High) => High,
        (Medium, _) or (_, Medium) => Medium,
        _ => "",
    };
}
