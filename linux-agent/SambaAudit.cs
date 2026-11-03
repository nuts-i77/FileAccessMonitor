using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Agent.Linux;

// One line of Samba's full_audit module, as set up by SambaConfig:
//   <user>|<client IP>|<client machine>|<share>|<share path>|<operation>|ok|<arguments...>
// create_file: <access mask>|<file|dir>|<disposition>|<path>
// renameat / rename: <old path>|<new path>
// unlinkat / unlink / rmdir: <path>
// Paths are absolute (Samba prefixes the share path); a relative one is taken as inside the share.
public record AuditLine(string User, string ClientIp, string ClientMachine, string Share, string SharePath,
    string Operation, string[] Args)
{
    public const int PrefixFields = 5;

    public static AuditLine? Parse(string message)
    {
        var parts = message.Split('|');
        if (parts.Length < PrefixFields + 3 || parts[PrefixFields + 1] != "ok") return null;
        return new AuditLine(parts[0], parts[1], parts[2], parts[3], parts[4], parts[PrefixFields],
            parts[(PrefixFields + 2)..]);
    }

    public string FullPath(string path)
    {
        if (path.StartsWith('/')) return Normalize(path);
        return Normalize(SharePath.TrimEnd('/') + "/" + (path == "." ? "" : path));
    }

    private static string Normalize(string path)
    {
        var p = path.Replace("/./", "/");
        while (p.Contains("//")) p = p.Replace("//", "/");
        if (p.EndsWith("/.")) p = p[..^2];
        return p.Length > 1 ? p.TrimEnd('/') : p;
    }
}

// What an audit line means for the access records. Type is empty when the line only shows that
// the path is a folder (opened as one without reading or writing data), which is remembered so
// that its later deletion is recorded as a folder's.
public record AuditAccess(string Path, string Type, bool IsFolder);

public static class AuditInterpreter
{
    private const long DeleteRight = 0x10000L;

    public static AuditAccess? Interpret(AuditLine line)
    {
        switch (line.Operation)
        {
            case "create_file":
            {
                // The access the client asked for, as in Windows auditing; deleting and renaming
                // are recorded when they happen (unlinkat / renameat)
                var mask = line.Args.Select(ParseMask).FirstOrDefault(m => m.HasValue);
                if (mask is not long m) return null;
                var type = AccessTypeOf(m & ~DeleteRight);
                var isFolder = line.Args.Contains("dir");
                return type == null && !isFolder ? null : new AuditAccess(line.FullPath(line.Args[^1]), type ?? "", isFolder);
            }
            case "renameat":
            case "rename":
            {
                if (line.Args.Length < 2) return null;
                // Samba 4.20 and later create a folder under a temporary name (".::TMPNAME:D:...")
                // and rename it into place: that is the folder being made, not a rename
                var from = line.Args[0];
                if (from[(from.LastIndexOf('/') + 1)..].StartsWith(".::TMPNAME:", StringComparison.Ordinal))
                    return new AuditAccess(line.FullPath(line.Args[1]), "", true);
                return new AuditAccess(line.FullPath(from), "Rename", false);
            }
            case "unlinkat":
            case "unlink":
                return new AuditAccess(line.FullPath(line.Args[^1]), "Delete", false);
            case "rmdir":
                return new AuditAccess(line.FullPath(line.Args[^1]), "Delete", true);
            default:
                return null;
        }
    }

    // Same rights as the Windows collector: data read/write (or generic read/write), not attributes
    internal static string? AccessTypeOf(long mask)
    {
        if ((mask & 0x40000006L) != 0) return "Write";
        if ((mask & 0x80000001L) != 0) return "Read";
        return null;
    }

    private static long? ParseMask(string s) =>
        s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
        && long.TryParse(s.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v : null;
}

// Reads Samba's audit lines from the systemd journal (journalctl), turns them into access records
// and puts them in the outbox. The journal cursor is kept with the outbox, so after a restart the
// agent continues where it stopped.
public class SambaAuditCollector(AgentOutbox outbox, ILogger<SambaAuditCollector> logger) : BackgroundService
{
    public const string SyslogIdentifier = "smbd_audit";
    private const int MaxBatchSize = 500;
    private static readonly Regex Suppressed = new(@"Suppressed (\d+) messages from (smbd|smb|samba)", RegexOptions.IgnoreCase);

    private readonly ReadMerger _readMerger = new();
    private readonly RecentFolders _recentFolders = new();
    private (string Path, HashSet<string> EventTypes)[] _paths = [];
    private RecordingRules _rules = new(new RecordingSettings());
    private DateTime _settingsTime = DateTime.MinValue;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Collecting Samba file accesses from the journal ({Identifier}).", SyslogIdentifier);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ReadJournalAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                logger.LogError(ex, "Reading the journal failed; retrying in 10 seconds.");
            }
            try { await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken); } catch (OperationCanceledException) { break; }
        }
    }

    private async Task ReadJournalAsync(CancellationToken ct)
    {
        var cursor = outbox.Position;
        if (cursor.Length > 0 && !await CursorStillInJournalAsync(cursor, ct))
        {
            logger.LogWarning("The journal no longer has the entry the agent stopped at; accesses in between may be missing.");
            outbox.Add(new AgentBatch { Gap = new AgentGap { AuditDetail = "reason=journalRotated", MessageKey = "gap.journalRotated" } });
        }

        var psi = Samba.StartInfo("journalctl",
        [
            "--follow", "--output=json", "--no-pager",
            cursor.Length > 0 ? "--after-cursor=" + cursor : "--lines=0",
            // Audit lines, and journald's notes about lines it dropped (rate limiting)
            "SYSLOG_IDENTIFIER=" + SyslogIdentifier, "+", "SYSLOG_IDENTIFIER=systemd-journald",
        ]);
        using var process = Process.Start(psi) ?? throw new InvalidOperationException("journalctl did not start.");
        using var kill = ct.Register(() => { try { process.Kill(); } catch (InvalidOperationException) { } });
        _ = process.StandardError.ReadToEndAsync(ct);

        var batch = new List<AccessRecord>(MaxBatchSize);
        string? lastCursor = null;
        var reader = process.StandardOutput;
        Task<string?>? pending = null;

        while (true)
        {
            pending ??= reader.ReadLineAsync(ct).AsTask();
            // Write what has been collected when no more lines arrive for a second
            if (batch.Count > 0 || lastCursor != null)
            {
                var done = await Task.WhenAny(pending, Task.Delay(TimeSpan.FromSeconds(1), ct));
                if (done != pending) { Flush(batch, ref lastCursor); continue; }
            }
            var line = await pending;
            pending = null;
            if (line == null) break; // journalctl exited

            if (Handle(line, batch) is { } entryCursor) lastCursor = entryCursor;
            if (batch.Count >= MaxBatchSize) Flush(batch, ref lastCursor);
        }
        Flush(batch, ref lastCursor);
        if (!ct.IsCancellationRequested)
            logger.LogWarning("journalctl exited (code {Code}).", process.HasExited ? process.ExitCode : -1);
    }

    // Returns the entry's cursor
    private string? Handle(string json, List<AccessRecord> batch)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var cursor = root.TryGetProperty("__CURSOR", out var c) ? c.GetString() : null;
        var message = MessageOf(root);
        var identifier = root.TryGetProperty("SYSLOG_IDENTIFIER", out var id) ? id.GetString() : null;
        if (message == null) return cursor;

        if (identifier == "systemd-journald")
        {
            if (Suppressed.Match(message) is { Success: true } m)
            {
                logger.LogWarning("journald dropped {Count} Samba audit lines (rate limit).", m.Groups[1].Value);
                outbox.Add(new AgentBatch
                {
                    Gap = new AgentGap { AuditDetail = $"reason=journalSuppressed, count={m.Groups[1].Value}",
                        MessageKey = "gap.journalSuppressed", Args = [m.Groups[1].Value] },
                });
            }
            return cursor;
        }

        var time = root.TryGetProperty("__REALTIME_TIMESTAMP", out var t)
                   && long.TryParse(t.GetString(), out var micros)
            ? DateTime.UnixEpoch.AddTicks(micros * 10)
            : DateTime.UtcNow;
        if (ToRecord(message, time) is { } record && _readMerger.ShouldRecord(record, _rules.MergeReadWindow))
            batch.Add(record);
        return cursor;
    }

    // MESSAGE is a string, or an array of bytes when it is not valid UTF-8
    private static string? MessageOf(JsonElement root)
    {
        if (!root.TryGetProperty("MESSAGE", out var m)) return null;
        return m.ValueKind switch
        {
            JsonValueKind.String => m.GetString(),
            JsonValueKind.Array => System.Text.Encoding.UTF8.GetString(m.EnumerateArray().Select(b => (byte)b.GetInt32()).ToArray()),
            _ => null,
        };
    }

    internal AccessRecord? ToRecord(string message, DateTime timeUtc)
    {
        if (AuditLine.Parse(message) is not { } line || AuditInterpreter.Interpret(line) is not { } access) return null;
        RefreshSettings();

        var path = access.Path;
        if (access.IsFolder) _recentFolders.Add(path);
        if (access.Type.Length == 0) return null;
        var matched = _paths.Length > 0 ? _paths.FirstOrDefault(p => IsUnderPath(path, p.Path)) : default;
        if (_paths.Length > 0 && matched == default) return null;
        var parent = ParentOf(path);
        _recentFolders.Add(parent);

        if (_rules.IsExcludedFile(NameOf(path)) || _rules.IsExcludedUser(line.User)) return null;
        var eventTypes = matched != default ? matched.EventTypes : null;
        var typeForFilter = access.Type == "Rename" ? "Delete" : access.Type; // as on Windows: renames go with deletions
        if (eventTypes != null && !eventTypes.Contains(typeForFilter)) return null;

        // Folders are recorded only when deleted or renamed (as on Windows)
        var isFolder = access.IsFolder || Directory.Exists(path);
        if (isFolder) _recentFolders.Add(path);
        isFolder |= _recentFolders.Contains(path);
        if (isFolder && access.Type is "Read" or "Write") return null;

        return new AccessRecord
        {
            FilePath = path, FileName = NameOf(path), FolderPath = parent,
            UserName = line.User, AccessType = access.Type, AccessTime = timeUtc,
            ClientIp = NormalizeIp(line.ClientIp),
            ClientMachine = string.IsNullOrEmpty(line.ClientMachine) ? null : line.ClientMachine,
            IsFolder = isFolder,
        };
    }

    // For tests: monitored folders and rules without settings.json
    internal void UseSettings((string Path, string[] EventTypes)[] paths, RecordingSettings rules)
    {
        _paths = paths.Select(p => (p.Path, new HashSet<string>(p.EventTypes, StringComparer.OrdinalIgnoreCase))).ToArray();
        _rules = new RecordingRules(rules);
        _settingsTime = DateTime.MaxValue;
    }

    private void Flush(List<AccessRecord> batch, ref string? lastCursor)
    {
        if (lastCursor == null) return;
        if (batch.Count > 0 && !outbox.Add(new AgentBatch { Records = batch.Select(AgentRecord.From).ToList() }))
            logger.LogError("The outbox is full ({Max} bytes); dropping {Count} records. Is the monitoring server reachable?",
                AgentOutbox.MaxBytes, batch.Count);
        outbox.SavePosition(lastCursor);
        batch.Clear();
        lastCursor = null;
    }

    private static async Task<bool> CursorStillInJournalAsync(string cursor, CancellationToken ct)
    {
        using var process = Process.Start(Samba.StartInfo("journalctl",
            ["--cursor=" + cursor, "--lines=1", "--output=json", "--no-pager", "--quiet"]))!;
        var output = await process.StandardOutput.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);
        return output.Contains(cursor, StringComparison.Ordinal);
    }

    private void RefreshSettings()
    {
        if (_settingsTime == DateTime.MaxValue) return; // set by a test
        var time = File.Exists(SettingsStore.DefaultPath) ? File.GetLastWriteTimeUtc(SettingsStore.DefaultPath) : DateTime.MinValue;
        if (time == _settingsTime) return;
        _settingsTime = time;
        var root = SettingsStore.Load();
        _paths = MonitoredPathList.Parse(root)
            .Select(p => (p.Path, new HashSet<string>(p.EventTypes, StringComparer.OrdinalIgnoreCase))).ToArray();
        _rules = new RecordingRules(RecordingSettings.Load());
    }

    // Linux paths are case-sensitive: /srv/share matches /srv/share/a.txt but not /srv/share2/a.txt
    internal static bool IsUnderPath(string path, string root)
    {
        var r = root.Length > 1 ? root.TrimEnd('/') : root;
        return path == r || path.StartsWith(r == "/" ? "/" : r + "/", StringComparison.Ordinal);
    }

    private static string NameOf(string path) => path[(path.LastIndexOf('/') + 1)..];

    private static string ParentOf(string path)
    {
        var i = path.LastIndexOf('/');
        return i <= 0 ? "/" : path[..i];
    }

    // "::ffff:192.0.2.10" -> "192.0.2.10"
    private static string? NormalizeIp(string ip) =>
        string.IsNullOrEmpty(ip) ? null : ip.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase) ? ip[7..] : ip;
}
