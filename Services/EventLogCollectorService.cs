using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Channels;
using System.Xml.Linq;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;

namespace FileAccessMonitor.Services;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class EventLogCollectorService : BackgroundService
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetSessionEnum(
        string? ServerName, string? UncClientName, string? UserName,
        int Level, out IntPtr BufPtr, int PrefMaxLen,
        out int EntriesRead, out int TotalEntries, ref int ResumeHandle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr Buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SESSION_INFO_10
    {
        public string sesi10_cname;    // "\\IP" or "\\hostname"
        public string sesi10_username;
        public uint sesi10_time;
        public uint sesi10_idle_time;
    }

    // Parsed event, so the EventRecord can be disposed on the watcher thread
    // Failure: the event has the Audit Failure keyword (a refused access)
    internal sealed record RawEvent(int Id, long RecordId, DateTime? TimeCreated, Dictionary<string, string> Data, bool Failure = false);

    private const long AuditFailureKeyword = 0x10000000000000L;

    private const int MaxBatchSize = 500;
    // Saving the position is cheap but not free; for events that produce no record
    // (logons etc.) it is enough to save it every few seconds.
    private static readonly TimeSpan PositionSaveInterval = TimeSpan.FromSeconds(5);

    // 4663: object access (read/write/delete)
    // 4659: handle requested with intent to delete (fired specifically for DELETE on modern Windows)
    // 4660: object deleted (follows the 4663 DELETE access of a deletion, but not of a rename)
    // 4656: handle requested, only the Audit Failure ones (refused access). The success ones are
    //       not read, so the existing success auditing adds no load.
    // 4670: permissions on an object were changed
    // 4624: logon (for IP/machine caching)
    // 5140: network share access (for IP/machine caching)
    // 4503599627370496 = 0x10000000000000, the Audit Failure keyword
    private const string XPathQuery = "*[System[(EventID=4663) or (EventID=4659) or (EventID=4660) or (EventID=4670)"
        + " or (EventID=4656 and band(Keywords,4503599627370496)) or (EventID=4624) or (EventID=5140)]]";

    private readonly IRecordSink _sink;
    private readonly ILogger<EventLogCollectorService> _logger;
    private readonly IConfiguration _config;
    private readonly DnsResolverService _dns;

    // Stamped on every record, so records from several file servers can be told apart
    internal static readonly string ServerName = Environment.MachineName;

    private readonly Channel<RawEvent> _queue = Channel.CreateUnbounded<RawEvent>(
        new UnboundedChannelOptions { SingleReader = true });

    // Maps "\Device\HarddiskVolumeX" -> "C:"
    private Dictionary<string, string> _deviceMap = new(StringComparer.OrdinalIgnoreCase);

    // Maps logon session id -> (IpAddress, WorkstationName)
    // Populated from Event 4624 (TargetLogonId) and Event 5140 (SubjectLogonId)
    private readonly ConcurrentDictionary<string, (string Ip, string Machine)> _logonCache = new();

    // Maps username (case-insensitive) -> (ClientAddress, ClientAddress)
    // Refreshed every 30s via NetSessionEnum — covers long-lived SMB sessions
    private readonly ConcurrentDictionary<string, (string Ip, string Machine)> _smbSessionCache
        = new(StringComparer.OrdinalIgnoreCase);

    private static readonly HashSet<string> SystemAccounts = new(StringComparer.OrdinalIgnoreCase)
    {
        "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"
    };

    // Monitored paths and recording rules, re-read when settings.json changes (checked at most once a second)
    private (string Path, HashSet<string> EventTypes)[] _pathConfigs = [];
    private DateTime _pathConfigsFileTime = DateTime.MinValue;
    private readonly Stopwatch _pathConfigsCheck = new();
    private RecordingRules _rules = new(new RecordingSettings());
    private volatile string[] _usnRoots = [];
    private bool _pathConfigsFixed;

    // Used only by the consumer task
    private readonly ReadMerger _readMerger = new();
    private readonly DeleteTracker _deleteTracker = new(path => File.Exists(path) || Directory.Exists(path));
    private readonly RecentFolders _recentFolders = new();
    private readonly DeniedMerger _deniedMerger = new();
    private readonly PermissionMerger _permissionMerger = new();

    // Creates and new names of renamed files come from the NTFS change journal (the Security log has
    // neither). Records that can use them wait briefly in the correlator; see UsnCorrelator.
    private readonly UsnCorrelator _usnCorrelator = new();
    private UsnJournalReader? _usnReader;
    private bool _usnEnabled = true;

    // Refused attempts by the same user on the same file with the same type are recorded once; the
    // window slides like ReadMerger's, so a client that keeps retrying makes one record.
    internal sealed class DeniedMerger
    {
        public static readonly TimeSpan Window = TimeSpan.FromSeconds(60);
        private const int MaxEntries = 50_000;
        private readonly Dictionary<(string User, string Path, string Type), DateTime> _last = new();

        public bool ShouldRecord(AccessRecord record)
        {
            var key = (record.UserName.ToUpperInvariant(), record.FilePath.ToUpperInvariant(), record.AccessType);
            var time = record.AccessTime;
            var merged = _last.TryGetValue(key, out var last) && (time - last).Duration() < Window;
            _last[key] = merged && last > time ? last : time;
            if (_last.Count > MaxEntries)
            {
                foreach (var old in _last.Where(kv => time - kv.Value >= Window).Select(kv => kv.Key).ToList())
                    _last.Remove(old);
                if (_last.Count > MaxEntries) _last.Clear();
            }
            return !merged;
        }
    }

    public EventLogCollectorService(
        IRecordSink sink,
        ILogger<EventLogCollectorService> logger,
        IConfiguration config,
        DnsResolverService dns)
    {
        _sink = sink;
        _dns = dns;
        _logger = logger;
        _config = config;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("EventLogCollectorService starting.");
        _deviceMap = BuildDeviceMap();
        _logger.LogInformation("Device map built: {Count} drives.", _deviceMap.Count);

        var excludeSystem = _config.GetValue("ExcludeSystemAccounts", true);
        var excludeProcesses = _config.GetSection("ExcludeProcessNames").Get<string[]>()
            ?? Array.Empty<string>();
        var excludeProcessSet = new HashSet<string>(excludeProcesses, StringComparer.OrdinalIgnoreCase);

        EnableFileShareAuditing();
        PreloadLogonCache();

        // Initial SMB session refresh, then every 30s
        RefreshSmbSessions();
        _ = Task.Run(async () =>
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken).ConfigureAwait(false);
                RefreshSmbSessions();
            }
        }, stoppingToken);

        GetPathConfigs(); // monitored folders and Recording settings, before the reader asks for them
        _usnReader = new UsnJournalReader(_usnCorrelator, _logger, () => _usnRoots, () => _usnEnabled,
            Path.Combine(AppPaths.DataDir, "usn-position.json"));
        _ = Task.Run(() => _usnReader.RunAsync(stoppingToken), stoppingToken);

        var lastRecordId = long.TryParse(await _sink.LoadPositionAsync(), out var savedId) ? savedId : 0;
        var consumer = Task.Run(() => ConsumeAsync(lastRecordId, excludeSystem, excludeProcessSet));

        EventLogWatcher? watcher = null;
        try
        {
            (watcher, var skipUpTo) = await CreateWatcherAsync(lastRecordId);
            watcher.EventRecordWritten += (_, e) => Enqueue(e, skipUpTo);
            watcher.Enabled = true;

            _logger.LogInformation("Watching Security event log for file access events.");
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException) { }
        catch (UnauthorizedAccessException)
        {
            _logger.LogError("Access denied to Security event log. Run as Administrator or SYSTEM.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error in EventLogCollectorService.");
        }
        finally
        {
            watcher?.Dispose();
            // Let the consumer write what is still queued (and the read position) before exiting
            _queue.Writer.TryComplete();
            await consumer;
            _logger.LogInformation("EventLogCollectorService stopped.");
        }
    }

    // Resume right after the last processed event, so events written while the service
    // was stopped (upgrade, reboot) are collected too, as long as they are still in the log.
    // Returns the watcher and the record id up to which events are already processed.
    private async Task<(EventLogWatcher Watcher, long SkipUpTo)> CreateWatcherAsync(long lastRecordId)
    {
        var query = new EventLogQuery("Security", PathType.LogName, XPathQuery);
        if (lastRecordId <= 0)
            return (new EventLogWatcher(query), 0); // first run: live events only

        var bookmark = FindBookmark(lastRecordId);
        if (bookmark != null)
        {
            _logger.LogInformation("Resuming after Security log record {RecordId}.", lastRecordId);
            return (new EventLogWatcher(query, bookmark, readExistingEvents: true), lastRecordId);
        }

        if (NewestRecordId() < lastRecordId)
        {
            // Record ids restarted (the log was cleared): everything in the log is new.
            _logger.LogWarning("The Security log was cleared since the last run; reading all events in it.");
            var clearedBy = FindLogClearedBy() ?? "-";
            await _sink.ReportGapAsync($"server={ServerName}, reason=logCleared, by={clearedBy}", "gap.cleared", clearedBy);
            return (new EventLogWatcher(query, null, readExistingEvents: true), 0);
        }

        // The last processed event has already been overwritten: read everything still in the log.
        var oldest = OldestRecordId();
        if (oldest > lastRecordId + 1)
        {
            _logger.LogWarning(
                "Security log records {From}-{To} were overwritten before they could be collected. Consider enlarging the Security log.",
                lastRecordId + 1, oldest - 1);
            var missedFrom = lastRecordId + 1;
            await _sink.ReportGapAsync($"server={ServerName}, missedRecords={missedFrom}-{oldest - 1}",
                "gap.overwritten", oldest - missedFrom, missedFrom, oldest - 1);
        }
        return (new EventLogWatcher(query, null, readExistingEvents: true), lastRecordId);
    }

    // Event 1102 ("The audit log was cleared") is the first record after a clear and names who did it.
    private string? FindLogClearedBy()
    {
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, "*[System[EventID=1102]]") { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            using var ev = reader.ReadEvent();
            if (ev == null) return null;
            var xml = XDocument.Parse(ev.ToXml());
            string? Value(string name) => xml.Descendants().FirstOrDefault(e => e.Name.LocalName == name)?.Value;
            var user = Value("SubjectUserName");
            var domain = Value("SubjectDomainName");
            return string.IsNullOrEmpty(user) ? null : string.IsNullOrEmpty(domain) ? user : $@"{domain}\{user}";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not read event 1102.");
            return null;
        }
    }

    private static EventBookmark? FindBookmark(long recordId)
    {
        var query = new EventLogQuery("Security", PathType.LogName, $"*[System[EventRecordID={recordId}]]");
        using var reader = new EventLogReader(query);
        using var ev = reader.ReadEvent();
        return ev?.Bookmark;
    }

    private static long OldestRecordId() => FirstRecordId(reverse: false);
    private static long NewestRecordId() => FirstRecordId(reverse: true);

    private static long FirstRecordId(bool reverse)
    {
        var query = new EventLogQuery("Security", PathType.LogName, "*") { ReverseDirection = reverse };
        using var reader = new EventLogReader(query);
        using var ev = reader.ReadEvent();
        return ev?.RecordId ?? 0;
    }

    private void Enqueue(EventRecordWrittenEventArgs e, long skipUpToRecordId)
    {
        if (e.EventException != null)
        {
            _logger.LogWarning(e.EventException, "Error reading from the Security event log.");
            return;
        }
        using var record = e.EventRecord;
        if (record?.RecordId is not long recordId || recordId <= skipUpToRecordId) return;

        try
        {
            var failure = ((record.Keywords ?? 0) & AuditFailureKeyword) != 0;
            _queue.Writer.TryWrite(new RawEvent(record.Id, recordId, record.TimeCreated, ParseEventData(record), failure));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error parsing event record {RecordId}.", recordId);
        }
    }

    // Single consumer: turns events into records and writes them in batches. Each batch is
    // saved together with the last Security log record id, in one transaction, so a crash
    // can neither lose nor duplicate records. The exception are DELETE accesses still waiting
    // to be told apart from renames (at most DeleteTracker.ConfirmTimeout) when the process is killed.
    private async Task ConsumeAsync(long lastRecordId, bool excludeSystem, HashSet<string> excludeProcessSet)
    {
        var batch = new List<AccessRecord>(MaxBatchSize);
        var savedRecordId = lastRecordId;
        var sinceSave = Stopwatch.StartNew();
        var reader = _queue.Reader;
        var newestEventUtc = DateTime.MinValue;

        void Add(AccessRecord record)
        {
            // Refused attempts are merged among themselves, never with successful reads
            if (record.Denied ? !_deniedMerger.ShouldRecord(record) : !_readMerger.ShouldRecord(record, _rules.MergeReadWindow))
                return;
            if (UsnCorrelator.NeedsCorrelation(record) && _usnReader?.Covers(record.FilePath) == true)
                _usnCorrelator.Hold(record, DateTime.UtcNow); // waits for the change journal, see UsnCorrelator
            else
                batch.Add(record);
        }

        while (await WaitForEventsAsync(reader))
        {
            while (batch.Count < MaxBatchSize && reader.TryRead(out var ev))
            {
                lastRecordId = ev.RecordId;
                if (ev.TimeCreated?.ToUniversalTime() is DateTime time && time > newestEventUtc)
                    newestEventUtc = time;
                try
                {
                    if (ProcessEvent(ev, excludeSystem, excludeProcessSet) is { } record) Add(record);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error processing event record {RecordId}.", ev.RecordId);
                }
            }
            _deleteTracker.Expire(newestEventUtc, DateTime.UtcNow).ForEach(Add);
            batch.AddRange(_usnCorrelator.Release(DateTime.UtcNow));

            if (batch.Count > 0 || (lastRecordId != savedRecordId && sinceSave.Elapsed >= PositionSaveInterval))
            {
                if (await _sink.SaveAsync(batch, lastRecordId.ToString()))
                {
                    savedRecordId = lastRecordId;
                    sinceSave.Restart();
                    _usnReader?.SavePositions();
                }
                batch.Clear();
            }
        }

        _deleteTracker.Expire(newestEventUtc, DateTime.UtcNow, force: true).ForEach(Add);
        batch.AddRange(_usnCorrelator.Release(DateTime.UtcNow, force: true));
        if (batch.Count > 0 || lastRecordId != savedRecordId)
            await _sink.SaveAsync(batch, lastRecordId.ToString());
    }

    // While DELETE accesses are pending, wakes up after the confirm timeout even without new
    // events, so they get resolved. Returns false once the queue is completed.
    private async Task<bool> WaitForEventsAsync(ChannelReader<RawEvent> reader)
    {
        var held = _usnCorrelator.HasHeld;
        if (!_deleteTracker.HasPending && !held) return await reader.WaitToReadAsync();
        // Records held for the change journal are released as it catches up: look again every second
        using var timeout = new CancellationTokenSource(held ? TimeSpan.FromSeconds(1) : DeleteTracker.ConfirmTimeout);
        try { return await reader.WaitToReadAsync(timeout.Token); }
        catch (OperationCanceledException) { return true; }
    }

    internal AccessRecord? ProcessEvent(RawEvent ev, bool excludeSystem, HashSet<string> excludeProcessSet)
    {
        var data = ev.Data;

        // Event 4624: cache TargetLogonId -> {IP, machine}
        if (ev.Id == 4624) { CacheLogonEvent(data); return null; }
        // Event 5140: cache SubjectLogonId -> {IP} — works for Kerberos sessions too
        if (ev.Id == 5140) { CacheShareEvent(data); return null; }
        // Event 4660: the file of a pending DELETE access was actually deleted
        if (ev.Id == 4660)
            return _deleteTracker.Confirm(data.GetValueOrDefault("ProcessId", ""), data.GetValueOrDefault("HandleId", ""));
        // Before any filter below: a DELETE access, recorded or not, ends a pending one on the same handle
        if (ev.Id == 4663 && (ParseMask(data.GetValueOrDefault("AccessMask", "0x0")) & DeleteRight) != 0)
            _deleteTracker.Release(data.GetValueOrDefault("ProcessId", ""), data.GetValueOrDefault("HandleId", ""));

        // 4656 with the failure keyword: a refused access (the XPath only lets those through)
        if (ev.Id == 4656 && (!ev.Failure || !_rules.Settings.RecordDenied || !IsAccessRefused(data)))
            return null;

        var objectType = data.GetValueOrDefault("ObjectType", "");
        if (!string.Equals(objectType, "File", StringComparison.OrdinalIgnoreCase))
            return null;

        var rawPath = data.GetValueOrDefault("ObjectName", "");
        if (string.IsNullOrWhiteSpace(rawPath) || rawPath == "-")
            return null;

        // Convert NT device path to drive letter path
        var filePath = ConvertToLocalPath(rawPath);

        // Skip NTFS alternate data streams (e.g. file.jpg:Zone.Identifier)
        if (filePath.Length > 2 && filePath.IndexOf(':', 2) >= 0)
            return null;

        // Find the matching monitored path config
        var pathConfigs = GetPathConfigs();
        var matchedConfig = pathConfigs.Length > 0
            ? pathConfigs.FirstOrDefault(c => IsUnderPath(filePath, c.Path))
            : default;

        if (pathConfigs.Length > 0 && matchedConfig == default)
            return null;
        _recentFolders.Add(Path.GetDirectoryName(filePath));

        var userName = data.GetValueOrDefault("SubjectUserName", "");
        if (excludeSystem && (userName.EndsWith("$") || SystemAccounts.Contains(userName)))
            return null;

        var processName = Path.GetFileName(data.GetValueOrDefault("ProcessName", ""));
        if (excludeProcessSet.Contains(processName))
            return null;

        var rules = _rules;
        var domainName = data.GetValueOrDefault("SubjectDomainName", "");
        var fullUserName = string.IsNullOrEmpty(domainName) || domainName == "-"
            ? userName
            : $@"{domainName}\{userName}";
        if (rules.IsExcludedFile(Path.GetFileName(filePath)) || rules.IsExcludedUser(fullUserName)
            || rules.IsExcludedProcess(processName))
            return null;

        var eventTypes = matchedConfig != default ? matchedConfig.EventTypes : AllEventTypes;
        var logonSessionId = data.GetValueOrDefault("SubjectLogonId", "");

        AccessRecord NewRecord(string accessType, bool isFolder)
        {
            _logonCache.TryGetValue(logonSessionId, out var clientInfo);
            // Fallback: use live SMB session table keyed by username
            if (string.IsNullOrEmpty(clientInfo.Ip))
                _smbSessionCache.TryGetValue(userName, out clientInfo);

            return new AccessRecord
            {
                FilePath = filePath,
                FileName = Path.GetFileName(filePath),
                FolderPath = Path.GetDirectoryName(filePath) ?? filePath,
                UserName = fullUserName,
                AccessType = accessType,
                AccessTime = ev.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
                ClientIp = string.IsNullOrEmpty(clientInfo.Ip) ? null : clientInfo.Ip,
                ClientMachine = ResolveMachine(clientInfo.Ip, clientInfo.Machine),
                IsFolder = isFolder,
                ServerName = ServerName,
            };
        }

        // Event 4670: permissions changed. Files and folders are recorded (the folder's own change
        // carries the text; the per-child events of a propagated change are dropped by the merger).
        if (ev.Id == 4670)
        {
            if (!eventTypes.Contains(AccessTypes.EventPermission)) return null;
            var change = PermissionChange.Analyze(data.GetValueOrDefault("OldSd"), data.GetValueOrDefault("NewSd"));
            if (change == null) return null;
            var time = ev.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow;
            if (!_permissionMerger.ShouldRecord(logonSessionId, filePath, time, change.Explicit)) return null;

            var folder = Directory.Exists(filePath);
            if (folder) _recentFolders.Add(filePath);
            var permission = NewRecord(AccessTypes.Permission, folder || _recentFolders.Contains(filePath));
            permission.Detail = change.Text;
            return permission;
        }

        // Event 4659 = "handle requested with intent to delete" → always Delete
        // Event 4663 = determine type from AccessMask. DELETE access is also used for renames
        // and moves, so it is decided later by the delete tracker.
        // Event 4656 (failure) = the type that was refused; never goes through the delete tracker.
        var mask = ParseMask(data.GetValueOrDefault("AccessMask", "0x0"));
        var denied = ev.Id == 4656;
        var deleteAccess = ev.Id == 4663 && (mask & DeleteRight) != 0;
        var accessType = denied ? ParseDeniedType(mask)
            : ev.Id == 4659 ? "Delete" : deleteAccess ? "Delete" : ParseAccessType(mask);
        if (accessType == null) return null;

        // Filter by per-path event types (skip if this access type is not monitored for this path).
        // A DELETE access can still turn out to be a write, so it is filtered when resolved.
        if (!deleteAccess && !eventTypes.Contains(accessType))
            return null;

        // Folders (the SACL applies to them too) are recorded only when deleted or renamed, or when
        // refused (opening or listing a forbidden folder is the typical probe).
        // A folder may already be gone when its deletion is processed, but its contents were
        // deleted before it, so it is then known as their parent. Checked last: touches the disk.
        var isFolder = Directory.Exists(filePath);
        if (isFolder) _recentFolders.Add(filePath);
        isFolder |= _recentFolders.Contains(filePath); // also when it is gone by now
        if (isFolder && !deleteAccess && !denied)
            return null;

        var record = NewRecord(accessType, isFolder);
        if (denied) record.Denied = true;
        if (!deleteAccess) return record;

        _deleteTracker.Add(data.GetValueOrDefault("ProcessId", ""), data.GetValueOrDefault("HandleId", ""),
            record, ParseAccessType(mask & ~DeleteRight), eventTypes, DateTime.UtcNow);
        return null;
    }

    private static Dictionary<string, string> ParseEventData(EventRecord record)
    {
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        var data = new Dictionary<string, string>();
        foreach (var e in XDocument.Parse(record.ToXml()).Descendants(ns + "Data"))
        {
            var name = e.Attribute("Name")?.Value;
            if (name != null) data[name] = e.Value;
        }
        return data;
    }

    private void EnableFileShareAuditing()
    {
        // Enable File Share auditing (Event 5140) via auditpol
        try
        {
            var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "auditpol",
                // GUID for "Audit File Share" subcategory — language-independent
                Arguments = "/set /subcategory:\"{0CCE9224-69AE-11D9-BED3-505054503030}\" /success:enable",
                UseShellExecute = false,
                CreateNoWindow = true
            });
            proc?.WaitForExit(5000);
            _logger.LogInformation("Audit File Share policy enabled.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not enable Audit File Share policy.");
        }
    }

    // Pre-populate logon cache from the last 30 days of Event 4624 (and 5140)
    // Reading newest-first so recent (still-active) sessions are stored first.
    private void PreloadLogonCache()
    {
        try
        {
            // 30 days in milliseconds
            const string preloadXpath =
                "*[System[(EventID=4624 or EventID=5140) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]";
            var preloadQuery = new EventLogQuery("Security", PathType.LogName, preloadXpath)
            {
                ReverseDirection = true  // newest first — most recent sessions win
            };
            using var reader = new EventLogReader(preloadQuery);
            int preloaded = 0;
            while (preloaded < 20000)
            {
                using var ev = reader.ReadEvent();
                if (ev == null) break;
                var data = ParseEventData(ev);
                if (ev.Id == 4624) CacheLogonEvent(data);
                else if (ev.Id == 5140) CacheShareEvent(data);
                preloaded++;
            }
            _logger.LogInformation("Session cache pre-populated: {Count} entries (scanned {Scanned}).",
                _logonCache.Count, preloaded);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not pre-populate session cache from history.");
        }
    }

    private void CacheLogonEvent(Dictionary<string, string> data)
    {
        var logonId = data.GetValueOrDefault("TargetLogonId", "");
        if (string.IsNullOrEmpty(logonId) || logonId == "0x0") return;

        var ip = data.GetValueOrDefault("IpAddress", "");
        var machine = data.GetValueOrDefault("WorkstationName", "");
        if (ip == "-" || ip == "::1" || ip == "127.0.0.1") ip = "";
        if (machine == "-") machine = "";

        if (string.IsNullOrEmpty(ip) && string.IsNullOrEmpty(machine)) return;

        _logonCache[logonId] = (ip, machine);

        if (_logonCache.Count > 5000)
        {
            var oldest = _logonCache.Keys.Take(500).ToList();
            foreach (var k in oldest) _logonCache.TryRemove(k, out _);
        }
    }

    // Event 5140: A network share object was accessed — has SubjectLogonId + IpAddress
    // This fires for Kerberos-authenticated SMB clients where 4624 may lack the IP.
    private void CacheShareEvent(Dictionary<string, string> data)
    {
        var logonId = data.GetValueOrDefault("SubjectLogonId", "");
        if (string.IsNullOrEmpty(logonId) || logonId == "0x0") return;

        var ip = data.GetValueOrDefault("IpAddress", "");
        if (ip == "-" || ip == "::1" || ip == "127.0.0.1") ip = "";
        if (string.IsNullOrEmpty(ip)) return;

        // Keep existing machine name if already known from 4624
        _logonCache.TryGetValue(logonId, out var existing);
        _logonCache[logonId] = (ip, existing.Machine ?? "");

        if (_logonCache.Count > 10000)
        {
            var oldest = _logonCache.Keys.Take(1000).ToList();
            foreach (var k in oldest) _logonCache.TryRemove(k, out _);
        }
    }

    private string? ResolveMachine(string ip, string machine)
    {
        // If machine name is empty or same as IP, try DNS reverse lookup
        var name = (machine == ip) ? "" : machine;
        if (string.IsNullOrEmpty(name))
            name = _dns.TryResolve(ip) ?? "";
        return string.IsNullOrEmpty(name) ? null : name;
    }

    private void RefreshSmbSessions()
    {
        try
        {
            int resumeHandle = 0;
            int result = NetSessionEnum(null, null, null, 10,
                out IntPtr buf, -1, out int entriesRead, out int totalEntries, ref resumeHandle);
            if (result != 0 || buf == IntPtr.Zero) return;
            try
            {
                int size = Marshal.SizeOf<SESSION_INFO_10>();
                _smbSessionCache.Clear();
                for (int i = 0; i < entriesRead; i++)
                {
                    var si = Marshal.PtrToStructure<SESSION_INFO_10>(IntPtr.Add(buf, i * size));
                    var user = si.sesi10_username ?? "";
                    var client = (si.sesi10_cname ?? "").TrimStart('\\');
                    if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(client)) continue;
                    _smbSessionCache[user] = (client, client);
                }
                _logger.LogDebug("SMB sessions refreshed: {Count} entries.", _smbSessionCache.Count);
            }
            finally { NetApiBufferFree(buf); }
        }
        catch (Exception ex) { _logger.LogDebug(ex, "SMB session refresh failed."); }
    }

    // Settings changes from the GUI take effect within a second, without re-reading the file per event.
    private (string Path, HashSet<string> EventTypes)[] GetPathConfigs()
    {
        if (_pathConfigsFixed) return _pathConfigs;
        if (_pathConfigsCheck.IsRunning && _pathConfigsCheck.Elapsed < TimeSpan.FromSeconds(1))
            return _pathConfigs;
        _pathConfigsCheck.Restart();

        var fileTime = File.Exists(SettingsStore.DefaultPath)
            ? File.GetLastWriteTimeUtc(SettingsStore.DefaultPath)
            : DateTime.MinValue;
        if (fileTime != _pathConfigsFileTime)
        {
            _pathConfigsFileTime = fileTime;
            var (configs, _) = FileAccessMonitor.Controllers.SettingsController.ReadSettingsDoc();
            _pathConfigs = configs
                .Select(c => (c.Path, new HashSet<string>(c.EventTypes, StringComparer.OrdinalIgnoreCase)))
                .ToArray();
            _rules = new RecordingRules(RecordingSettings.Load());
            _usnRoots = _pathConfigs.Select(c => c.Path).ToArray();
            _usnEnabled = UsnCorrelationEnabled();
        }
        return _pathConfigs;
    }

    // Recording.UsnCorrelation in settings.json (not part of RecordingSettings): default on
    private static bool UsnCorrelationEnabled()
    {
        try
        {
            return SettingsStore.Load()[RecordingSettings.SettingsKey]?["UsnCorrelation"]?.GetValue<bool>() ?? true;
        }
        catch (Exception ex) when (ex is InvalidOperationException or FormatException)
        {
            return true;
        }
    }

    // Tests: fixed monitored paths and rules instead of settings.json
    internal void UseConfigForTest((string Path, HashSet<string> EventTypes)[] paths, RecordingRules rules)
    {
        _pathConfigs = paths;
        _rules = rules;
        _pathConfigsFixed = true;
    }

    private string ConvertToLocalPath(string ntPath)
    {
        foreach (var kvp in _deviceMap)
        {
            if (ntPath.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
                return kvp.Value + ntPath[kvp.Key.Length..];
        }
        return ntPath;
    }

    private Dictionary<string, string> BuildDeviceMap()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var sb = new StringBuilder(512);
        foreach (var drive in Directory.GetLogicalDrives())
        {
            var letter = drive.TrimEnd('\\', '/');
            sb.Clear();
            try
            {
                if (QueryDosDevice(letter, sb, sb.Capacity) > 0)
                    map[sb.ToString()] = letter;
            }
            catch { /* skip inaccessible drives */ }
        }
        return map;
    }

    // True if filePath is root itself or inside it (D:\Share matches D:\Share\a.txt but not D:\Share2\a.txt)
    internal static bool IsUnderPath(string filePath, string root)
    {
        var r = root.TrimEnd('\\', '/');
        return filePath.Equals(r, StringComparison.OrdinalIgnoreCase)
            || filePath.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase);
    }

    internal const long DeleteRight = 0x10000L;

    // Types used when no monitored path is configured (all folders are recorded)
    private static readonly IReadOnlySet<string> AllEventTypes =
        new HashSet<string>(["Read", "Write", "Delete", "Permission"], StringComparer.OrdinalIgnoreCase);

    // A SACL failure entry only fires when the access check failed. If the event names a status,
    // it must be STATUS_ACCESS_DENIED; others (sharing violation, ...) are not a refusal.
    private const long StatusAccessDenied = 0xC0000022L;

    internal static bool IsAccessRefused(Dictionary<string, string> data)
    {
        var status = data.GetValueOrDefault("Status", "");
        return string.IsNullOrWhiteSpace(status) || status == "-" || ParseMask(status) == StatusAccessDenied;
    }

    // What was refused, from the requested access mask (same classification as a granted access)
    internal static string? ParseDeniedType(long mask) => ParseAccessType(mask);

    internal static long ParseMask(string accessMaskStr)
    {
        if (accessMaskStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return long.TryParse(accessMaskStr[2..], System.Globalization.NumberStyles.HexNumber, null, out var hex) ? hex : 0;
        return long.TryParse(accessMaskStr, out var mask) ? mask : 0;
    }

    internal static string? ParseAccessType(string accessMaskStr) => ParseAccessType(ParseMask(accessMaskStr));

    internal static string? ParseAccessType(long mask)
    {
        // DELETE
        if ((mask & DeleteRight) != 0) return "Delete";
        // WriteData (0x2) or AppendData (0x4) only — exclude WriteEA(0x10) and WriteAttributes(0x100)
        if ((mask & 0x40000002L) != 0 || (mask & 0x2L) != 0 || (mask & 0x4L) != 0)
            return "Write";
        // ReadData (0x1) only — exclude ReadEA(0x8) and ReadAttributes(0x80)
        if ((mask & 0x80000000L) != 0 || (mask & 0x1L) != 0)
            return "Read";

        return null;
    }
}
