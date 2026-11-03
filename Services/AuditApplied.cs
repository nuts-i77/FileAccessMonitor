using System.Text.Json.Nodes;

namespace FileAccessMonitor.Services;

// "AuditApplied" in this server's settings.json: which version of the auditing set-up each
// monitored folder has ("<server>|<path>" -> version). 1.9 audits refused attempts and permission
// changes too, which needs the SACL (Windows) or the Samba audit block (Linux) to be written again,
// so a folder below the current version is shown with a "Re-apply" notice until an Admin does.
public static class AuditApplied
{
    public const string SettingsKey = "AuditApplied";
    public const int CurrentVersion = 19;

    private static string Key(string server, string path) => server + "|" + path;

    // Folder path -> version, for one server (paths compared case-insensitively)
    public static Dictionary<string, int> For(JsonObject root, string server)
    {
        var result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (root[SettingsKey] is not JsonObject map) return result;
        var prefix = server + "|";
        foreach (var (key, value) in map)
            if (key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                && value is JsonValue v && v.TryGetValue<int>(out var version))
                result[key[prefix.Length..]] = version;
        return result;
    }

    public static void Set(JsonObject root, string server, string path)
    {
        Remove(root, server, path);
        var map = root[SettingsKey] as JsonObject ?? new JsonObject();
        map[Key(server, path)] = CurrentVersion;
        root[SettingsKey] = map;
    }

    public static void Remove(JsonObject root, string server, string path)
    {
        if (root[SettingsKey] is not JsonObject map) return;
        foreach (var key in map.Select(kv => kv.Key).Where(k => k.Equals(Key(server, path), StringComparison.OrdinalIgnoreCase)).ToList())
            map.Remove(key);
    }
}
