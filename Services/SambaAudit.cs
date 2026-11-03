using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using FileAccessMonitor.Models;

namespace FileAccessMonitor.Services;

// One line of Samba's full_audit module, as set up by SambaConfig:
//   <user>|<client IP>|<client machine>|<share>|<share path>|<operation>|<status>|<arguments...>
// status: "ok", or "fail (<strerror>)" for the operations in the failure list, e.g.
//   ...|create_file|fail (Permission denied)|0x120089|file|open|/srv/share/docs/a.txt
// create_file: <access mask>|<file|dir>|<disposition>|<path>
// renameat / rename: <old path>|<new path>
// unlinkat / unlink / rmdir: <path>
// fset_nt_acl / sys_acl_set_fd: <path>; fchmod: <path>|<mode in octal>; fchown: <path>|<uid>|<gid>
// Paths are absolute (Samba prefixes the share path); a relative one is taken as inside the share.
// Status is appended last so that code building a line without it still compiles.
public record AuditLine(string User, string ClientIp, string ClientMachine, string Share, string SharePath,
    string Operation, string[] Args, string Status = "ok")
{
    public const int PrefixFields = 5;

    // The operations Samba is asked to log when they fail (full_audit:failure)
    private static readonly HashSet<string> FailureOperations =
        ["create_file", "unlinkat", "unlink", "rmdir", "renameat", "rename"];

    public bool Ok => Status == "ok";

    // Lines of successful operations, and of failed ones that are logged for refused accesses
    // (whether a failure was a refusal is for AuditInterpreter to decide)
    public static AuditLine? Parse(string message)
    {
        var parts = message.Split('|');
        if (parts.Length < PrefixFields + 3) return null;
        var status = parts[PrefixFields + 1];
        var line = new AuditLine(parts[0], parts[1], parts[2], parts[3], parts[4], parts[PrefixFields],
            parts[(PrefixFields + 2)..], status);
        if (line.Ok) return line;
        return status.StartsWith("fail", StringComparison.Ordinal) && FailureOperations.Contains(line.Operation) ? line : null;
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

// The error texts (strerror, in the language smbd runs in) of a refused access: EACCES and EPERM.
// Every other failure (no such file, busy, ...) is not a refusal.
public static class SambaErrno
{
    private static readonly string[] DeniedTexts =
    [
        "Permission denied", "Operation not permitted",
        "許可がありません", "許可されていない操作です", // Japanese glibc
    ];

    // status: "fail (Permission denied)"
    public static bool IsDenied(string status) =>
        status.StartsWith("fail", StringComparison.Ordinal) && DeniedTexts.Any(t => status.Contains(t, StringComparison.OrdinalIgnoreCase));
}

// What an audit line means for the access records. Type is empty when the line only shows that
// the path is a folder (opened as one without reading or writing data), which is remembered so
// that its later deletion is recorded as a folder's. Denied: the access was refused. NewPath: where
// a renamed or moved file went. Detail: what a permission change was (null when not known).
public record AuditAccess(string Path, string Type, bool IsFolder, string? NewPath = null, bool Denied = false,
    string? Detail = null);

public static class AuditInterpreter
{
    private const long DeleteRight = 0x10000L;

    public static AuditAccess? Interpret(AuditLine line)
    {
        // A failed operation matters only when the access was refused
        var denied = !line.Ok;
        if (denied && !SambaErrno.IsDenied(line.Status)) return null;

        switch (line.Operation)
        {
            case "create_file":
            {
                // The access the client asked for, as in Windows auditing; deleting and renaming
                // are recorded when they happen (unlinkat / renameat)
                var mask = line.Args.Select(ParseMask).FirstOrDefault(m => m.HasValue);
                if (mask is not long m) return null;
                var isFolder = line.Args.Contains("dir");
                if (denied)
                {
                    // What was refused: delete, write or read access (anything else, such as
                    // attributes, is not auditing material)
                    var refused = (m & DeleteRight) != 0 ? "Delete" : AccessTypeOf(m);
                    return refused == null ? null : new AuditAccess(line.FullPath(line.Args[^1]), refused, isFolder, Denied: true);
                }
                // A file made by this call. The other dispositions that can create one (open_if,
                // overwrite_if, supersede) cannot be told from opening an existing file.
                if (!isFolder && line.Args.Length >= 4 && line.Args[2] == "create")
                    return new AuditAccess(line.FullPath(line.Args[^1]), AccessTypes.Create, false);
                var type = AccessTypeOf(m & ~DeleteRight);
                return type == null && !isFolder ? null : new AuditAccess(line.FullPath(line.Args[^1]), type ?? "", isFolder);
            }
            case "renameat":
            case "rename":
            {
                if (line.Args.Length < 2) return null;
                // Samba 4.20 and later create a folder under a temporary name (".::TMPNAME:D:...")
                // and rename it into place: that is the folder being made, not a rename
                var from = line.Args[0];
                if (!denied && from[(from.LastIndexOf('/') + 1)..].StartsWith(".::TMPNAME:", StringComparison.Ordinal))
                    return new AuditAccess(line.FullPath(line.Args[1]), "", true);
                return new AuditAccess(line.FullPath(from), AccessTypes.Rename, false, NewPath: line.FullPath(line.Args[1]), Denied: denied);
            }
            case "unlinkat":
            case "unlink":
                return new AuditAccess(line.FullPath(line.Args[^1]), AccessTypes.Delete, false, Denied: denied);
            case "rmdir":
                return new AuditAccess(line.FullPath(line.Args[^1]), AccessTypes.Delete, true, Denied: denied);

            // Permission changes. No before / after is available on Linux. fset_nt_acl is what SMB
            // clients use for ACLs and owners; fchmod, fchown and sys_acl_set_fd are understood but
            // not logged by default (Samba itself calls them when it creates files).
            case "fset_nt_acl":
            case "sys_acl_set_fd":
                return line.Args.Length == 0 ? null : new AuditAccess(line.FullPath(line.Args[0]), AccessTypes.Permission, false);
            case "fchmod":
                return line.Args.Length < 2 ? null
                    : new AuditAccess(line.FullPath(line.Args[0]), AccessTypes.Permission, false, Detail: "mode " + ModeText(line.Args[1]));
            case "fchown":
                return line.Args.Length < 3 ? null
                    : new AuditAccess(line.FullPath(line.Args[0]), AccessTypes.Permission, false,
                        Detail: $"owner uid={line.Args[1]} gid={line.Args[2]}");
            default:
                return null;
        }
    }

    // Samba prints the mode in octal ("644"); shown as 0644
    private static string ModeText(string mode) => mode.Length is > 0 and < 4 ? mode.PadLeft(4, '0') : mode;

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
// and hands them to the record sink: the outbox on a Linux agent, the database on a Linux
// monitoring server that also collects. The journal cursor is saved with them, so after a restart
// collection continues where it stopped.
[System.Runtime.Versioning.SupportedOSPlatform("linux")]
public class SambaAuditCollector(IRecordSink sink, ILogger<SambaAuditCollector> logger) : BackgroundService
{
    public const string SyslogIdentifier = "smbd_audit";
    private const int MaxBatchSize = 500;
    private static readonly Regex Suppressed = new(@"Suppressed (\d+) messages from (smbd|smb|samba)", RegexOptions.IgnoreCase);

    private readonly ReadMerger _readMerger = new();
    private readonly DeniedMerger _deniedMerger = new(DeniedMerger.DeniedWindow);
    private readonly DeniedMerger _permissionMerger = new(DeniedMerger.PermissionWindow);
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
        var cursor = await sink.LoadPositionAsync();
        if (cursor.Length > 0 && !await CursorStillInJournalAsync(cursor, ct))
        {
            logger.LogWarning("The journal no longer has the entry collection stopped at; accesses in between may be missing.");
            await sink.ReportGapAsync($"server={Environment.MachineName}, reason=journalRotated", "gap.journalRotated");
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

        async Task FlushAsync()
        {
            if (lastCursor == null) return;
            await sink.SaveAsync(batch, lastCursor); // logs and drops the batch if it cannot be kept
            batch.Clear();
            lastCursor = null;
        }

        while (true)
        {
            pending ??= reader.ReadLineAsync(ct).AsTask();
            // Write what has been collected when no more lines arrive for a second
            if (batch.Count > 0 || lastCursor != null)
            {
                var done = await Task.WhenAny(pending, Task.Delay(TimeSpan.FromSeconds(1), ct));
                if (done != pending) { await FlushAsync(); continue; }
            }
            var line = await pending;
            pending = null;
            if (line == null) break; // journalctl exited

            if (await HandleAsync(line, batch) is { } entryCursor) lastCursor = entryCursor;
            if (batch.Count >= MaxBatchSize) await FlushAsync();
        }
        await FlushAsync();
        if (!ct.IsCancellationRequested)
            logger.LogWarning("journalctl exited (code {Code}).", process.HasExited ? process.ExitCode : -1);
    }

    // Returns the entry's cursor
    private async Task<string?> HandleAsync(string json, List<AccessRecord> batch)
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
                await sink.ReportGapAsync($"server={Environment.MachineName}, reason=journalSuppressed, count={m.Groups[1].Value}",
                    "gap.journalSuppressed", long.Parse(m.Groups[1].Value));
            }
            return cursor;
        }

        var time = root.TryGetProperty("__REALTIME_TIMESTAMP", out var t)
                   && long.TryParse(t.GetString(), out var micros)
            ? DateTime.UnixEpoch.AddTicks(micros * 10)
            : DateTime.UtcNow;
        if (ToRecord(message, time) is { } record && ShouldKeep(record))
            batch.Add(record);
        return cursor;
    }

    // Repeats are merged: reads (not the denied ones, which have their own merger), refused
    // accesses and permission changes
    private bool ShouldKeep(AccessRecord record) =>
        record.Denied ? _deniedMerger.ShouldRecord(record)
        : record.AccessType == AccessTypes.Permission ? _permissionMerger.ShouldRecord(record)
        : _readMerger.ShouldRecord(record, _rules.MergeReadWindow);

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
        if (access.Denied && !_rules.Settings.RecordDenied) return null;
        var eventTypes = matched != default ? matched.EventTypes : null;
        // As on Windows: creating goes with writing, renaming with deleting
        if (eventTypes != null && !eventTypes.Contains(AccessTypes.EventTypeOf(access.Type))) return null;

        // Folders are recorded only when deleted or renamed, or when their permissions change or
        // an access to them is refused (as on Windows)
        var isFolder = access.IsFolder || Directory.Exists(path);
        if (isFolder) _recentFolders.Add(path);
        isFolder |= _recentFolders.Contains(path);
        if (isFolder && !access.Denied && access.Type is "Read" or "Write" or "Create") return null;

        return new AccessRecord
        {
            FilePath = path, FileName = NameOf(path), FolderPath = parent,
            UserName = line.User, AccessType = access.Type, AccessTime = timeUtc,
            ClientIp = NormalizeIp(line.ClientIp),
            ClientMachine = string.IsNullOrEmpty(line.ClientMachine) ? null : line.ClientMachine,
            IsFolder = isFolder,
            Denied = access.Denied,
            NewPath = access.NewPath is { Length: > 2000 } np ? np[..2000] : access.NewPath,
            Detail = access.Detail,
            ServerName = Environment.MachineName, // used when collecting on the monitoring server itself
        };
    }

    // For tests: monitored folders and rules without settings.json
    internal void UseSettings((string Path, string[] EventTypes)[] paths, RecordingSettings rules)
    {
        _paths = paths.Select(p => (p.Path, new HashSet<string>(p.EventTypes, StringComparer.OrdinalIgnoreCase))).ToArray();
        _rules = new RecordingRules(rules);
        _settingsTime = DateTime.MaxValue;
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
