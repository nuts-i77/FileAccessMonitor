using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;

namespace FileAccessMonitor.Services;

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

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<EventLogCollectorService> _logger;
    private readonly IConfiguration _config;
    private readonly DnsResolverService _dns;

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

    public EventLogCollectorService(
        IServiceScopeFactory scopeFactory,
        ILogger<EventLogCollectorService> logger,
        IConfiguration config,
        DnsResolverService dns)
    {
        _scopeFactory = scopeFactory;
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

        // Enable File Share auditing (Event 5140) via auditpol
        try
        {
            var proc = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
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

        // Pre-populate logon cache from the last 30 days of Event 4624 (and 5140)
        // Reading newest-first so recent (still-active) sessions are stored first.
        try
        {
            // 30 days in milliseconds
            const string preloadXpath =
                "*[System[(EventID=4624 or EventID=5140 or EventID=4659) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]";
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
                if (ev.Id == 4624) CacheLogonEvent(ev);
                else if (ev.Id == 5140) CacheShareEvent(ev);
                preloaded++;
            }
            _logger.LogInformation("Session cache pre-populated: {Count} entries (scanned {Scanned}).",
                _logonCache.Count, preloaded);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not pre-populate session cache from history.");
        }

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

        // 4663: object access (read/write/delete)
        // 4659: handle requested with intent to delete (fired specifically for DELETE on modern Windows)
        // 4624: logon (for IP/machine caching)
        // 5140: network share access (for IP/machine caching)
        const string xpathQuery = "*[System[(EventID=4663) or (EventID=4659) or (EventID=4624) or (EventID=5140)]]";

        EventLogWatcher? watcher = null;
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, xpathQuery);
            watcher = new EventLogWatcher(query);
            // Read monitoredPaths from config on each event so GUI changes take effect immediately
            watcher.EventRecordWritten += (_, e) =>
                OnEventWritten(e.EventRecord, excludeSystem, excludeProcessSet);
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
            _logger.LogInformation("EventLogCollectorService stopped.");
        }
    }

    private void OnEventWritten(
        EventRecord? record,
        bool excludeSystem,
        HashSet<string> excludeProcessSet)
    {
        if (record == null) return;

        try
        {
            var xml = record.ToXml();
            var doc = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";

            var data = doc.Descendants(ns + "Data")
                .Where(e => e.Attribute("Name") != null)
                .ToDictionary(e => e.Attribute("Name")!.Value, e => e.Value);

            // Event 4624: cache TargetLogonId -> {IP, machine}
            if (record.Id == 4624) { CacheLogonEvent(record); return; }
            // Event 5140: cache SubjectLogonId -> {IP} — works for Kerberos sessions too
            if (record.Id == 5140) { CacheShareEvent(record); return; }

            var pathConfigs = ReadMonitoredPathConfigsFromFile();

            var objectType = data.GetValueOrDefault("ObjectType", "");
            if (!string.Equals(objectType, "File", StringComparison.OrdinalIgnoreCase))
                return;

            var rawPath = data.GetValueOrDefault("ObjectName", "");
            if (string.IsNullOrWhiteSpace(rawPath) || rawPath == "-")
                return;

            // Convert NT device path to drive letter path
            var filePath = ConvertToLocalPath(rawPath);

            // Skip NTFS alternate data streams (e.g. file.jpg:Zone.Identifier)
            if (filePath.Length > 2 && filePath.IndexOf(':', 2) >= 0)
                return;

            // Skip directory accesses (SACL fires for folders too)
            if (Directory.Exists(filePath))
                return;

            // Find the matching monitored path config
            var matchedConfig = pathConfigs.Length > 0
                ? pathConfigs.FirstOrDefault(c => IsUnderPath(filePath, c.Path))
                : default;

            if (pathConfigs.Length > 0 && matchedConfig == default)
                return;

            var userName = data.GetValueOrDefault("SubjectUserName", "");
            var domainName = data.GetValueOrDefault("SubjectDomainName", "");
            var processName = Path.GetFileName(data.GetValueOrDefault("ProcessName", ""));
            var logonSessionId = data.GetValueOrDefault("SubjectLogonId", "");
            _logonCache.TryGetValue(logonSessionId, out var clientInfo);
            // Fallback: use live SMB session table keyed by username
            if (string.IsNullOrEmpty(clientInfo.Ip))
                _smbSessionCache.TryGetValue(userName, out clientInfo);

            if (excludeSystem && (userName.EndsWith("$") || SystemAccounts.Contains(userName)))
                return;

            if (excludeProcessSet.Contains(processName))
                return;

            // Event 4659 = "handle requested with intent to delete" → always Delete
            // Event 4663 = determine type from AccessMask
            string? accessType;
            if (record.Id == 4659)
            {
                accessType = "Delete";
            }
            else
            {
                var accessMaskStr = data.GetValueOrDefault("AccessMask", "0x0");
                accessType = ParseAccessType(accessMaskStr);
                if (accessType == null) return;
            }

            // Filter by per-path event types (skip if this access type is not monitored for this path)
            if (matchedConfig != default
                && !matchedConfig.EventTypes.Contains(accessType, StringComparer.OrdinalIgnoreCase))
                return;

            var fullUserName = string.IsNullOrEmpty(domainName) || domainName == "-"
                ? userName
                : $@"{domainName}\{userName}";

            var accessRecord = new AccessRecord
            {
                FilePath = filePath,
                FileName = Path.GetFileName(filePath),
                FolderPath = Path.GetDirectoryName(filePath) ?? filePath,
                UserName = fullUserName,
                AccessType = accessType,
                AccessTime = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
                ClientIp = string.IsNullOrEmpty(clientInfo.Ip) ? null : clientInfo.Ip,
                ClientMachine = ResolveMachine(clientInfo.Ip, clientInfo.Machine)
            };

            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            db.AccessRecords.Add(accessRecord);
            db.SaveChanges();

            _logger.LogDebug("Recorded: {Type} {Path} by {User}", accessType, filePath, fullUserName);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error processing event record.");
        }
    }

    private void CacheLogonEvent(EventRecord record)
    {
        try
        {
            var xml = record.ToXml();
            var doc = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var data = doc.Descendants(ns + "Data")
                .Where(e => e.Attribute("Name") != null)
                .ToDictionary(e => e.Attribute("Name")!.Value, e => e.Value);

            var logonId = data.GetValueOrDefault("TargetLogonId", "");
            if (string.IsNullOrEmpty(logonId) || logonId == "0x0") return;

            var logonType = data.GetValueOrDefault("LogonType", "");
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
        catch { }
    }

    // Event 5140: A network share object was accessed — has SubjectLogonId + IpAddress
    // This fires for Kerberos-authenticated SMB clients where 4624 may lack the IP.
    private void CacheShareEvent(EventRecord record)
    {
        try
        {
            var xml = record.ToXml();
            var doc = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var data = doc.Descendants(ns + "Data")
                .Where(e => e.Attribute("Name") != null)
                .ToDictionary(e => e.Attribute("Name")!.Value, e => e.Value);

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
        catch { }
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

    private static readonly string SettingsFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "FileAccessMonitor", "settings.json");

    private static (string Path, HashSet<string> EventTypes)[] ReadMonitoredPathConfigsFromFile()
    {
        var (configs, _) = FileAccessMonitor.Controllers.SettingsController.ReadSettingsDoc();
        return configs.Select(c => (c.Path, new HashSet<string>(c.EventTypes, StringComparer.OrdinalIgnoreCase))).ToArray();
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

    internal static string? ParseAccessType(string accessMaskStr)
    {
        long mask;
        if (accessMaskStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (!long.TryParse(accessMaskStr[2..],
                System.Globalization.NumberStyles.HexNumber, null, out mask))
                return null;
        }
        else if (!long.TryParse(accessMaskStr, out mask))
        {
            return null;
        }

        // DELETE
        if ((mask & 0x10000L) != 0) return "Delete";
        // WriteData (0x2) or AppendData (0x4) only — exclude WriteEA(0x10) and WriteAttributes(0x100)
        if ((mask & 0x40000002L) != 0 || (mask & 0x2L) != 0 || (mask & 0x4L) != 0)
            return "Write";
        // ReadData (0x1) only — exclude ReadEA(0x8) and ReadAttributes(0x80)
        if ((mask & 0x80000000L) != 0 || (mask & 0x1L) != 0)
            return "Read";

        return null;
    }
}
