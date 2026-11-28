using System.Collections.Concurrent;

namespace FileAccessMonitor.Services;

// The change journal of one drive that holds monitored folders, as the Windows collector last found it.
// Volume: "E:" (or the folder itself for a network path). State: one of JournalStates. Format: the file
// system when the drive has none (FAT32, exFAT, ...).
public record JournalVolume(string Volume, string State, string? Format = null);

public static class JournalStates
{
    public const string On = "on";                    // read: creations and new names are recorded
    public const string Off = "off";                  // NTFS / ReFS without a journal
    public const string Unsupported = "unsupported";  // a file system without journals (FAT32, exFAT, ...)
    public const string Network = "network";          // a network path
    public const string Error = "error";              // the drive or its journal cannot be read
    public const string Disabled = "disabled";        // Recording: the journal is not used

    public static readonly IReadOnlySet<string> All = new HashSet<string> { On, Off, Unsupported, Network, Error, Disabled };
}

// What the collector found, for its heartbeat (the reader and the sender are in the same process)
public static class UsnJournalStatus
{
    // The job that creates the journal of a monitored folder's drive (Settings → Monitored folders)
    public const string CreateJobType = "createJournal";

    // The list with one drive marked as on (after its journal was created, before the next heartbeat says so)
    public static List<JournalVolume> WithOn(IReadOnlyList<JournalVolume>? volumes, string drive, string? format) =>
        (volumes ?? []).Where(v => !string.Equals(v.Volume, drive, StringComparison.OrdinalIgnoreCase))
            .Append(new JournalVolume(drive, JournalStates.On, format)).ToList();

    private static volatile IReadOnlyList<JournalVolume>? _current;
    private static int _recheck;

    // Bumped after a journal was created, so that the reader looks at once instead of within a minute
    public static int RecheckCount => Volatile.Read(ref _recheck);
    public static void RequestRecheck() => Interlocked.Increment(ref _recheck);

    // null: not known (not Windows, or the reader has not looked yet)
    public static IReadOnlyList<JournalVolume>? Current
    {
        get => _current;
        set => _current = value;
    }

    // A heartbeat's list, checked: at most one entry per drive, known states only, short strings
    public static List<JournalVolume>? Clean(IEnumerable<JournalVolume?>? volumes)
    {
        if (volumes == null) return null;
        var list = new List<JournalVolume>();
        foreach (var v in volumes)
        {
            if (v == null || string.IsNullOrWhiteSpace(v.Volume) || v.Volume.Length > 260 || !JournalStates.All.Contains(v.State))
                continue;
            if (list.Any(e => string.Equals(e.Volume, v.Volume, StringComparison.OrdinalIgnoreCase))) continue;
            var format = v.Format is { Length: > 0 and <= 32 } f ? f : null;
            list.Add(new JournalVolume(v.Volume, v.State, format));
            if (list.Count >= 64) break;
        }
        return list;
    }

    // The entry for a monitored folder: its drive letter, or the folder itself for a network path
    public static JournalVolume? For(IReadOnlyList<JournalVolume>? volumes, string path)
    {
        if (volumes == null) return null;
        var key = DriveOf(path) ?? path;
        return volumes.FirstOrDefault(v => string.Equals(v.Volume, key, StringComparison.OrdinalIgnoreCase));
    }

    // "E:" for "e:\share\x"; null for a network path and the like
    public static string? DriveOf(string path) =>
        path.Length >= 2 && path[1] == ':' && char.IsAsciiLetter(path[0]) ? char.ToUpperInvariant(path[0]) + ":" : null;
}

// The journal states the agents reported (kept in memory: after a restart of the web part they come
// back with each agent's next heartbeat, a minute at most)
public class AgentJournalStates
{
    private readonly ConcurrentDictionary<string, IReadOnlyList<JournalVolume>> _byAgent = new();

    public void Set(string agentId, IReadOnlyList<JournalVolume>? volumes)
    {
        if (volumes == null) _byAgent.TryRemove(agentId, out _);
        else _byAgent[agentId] = volumes;
    }

    public IReadOnlyList<JournalVolume>? Get(string agentId) => _byAgent.TryGetValue(agentId, out var v) ? v : null;
}
