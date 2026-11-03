using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace FileAccessMonitor.Services;

// The parts of an agent shared by the Windows service and the Linux agent (linux-agent/): its
// registration, the outbox, sending, settings from the monitoring server, and jobs. What differs
// per platform (how auditing is set up and checked) comes through IAgentPlatform.

// Agent mode: when agent.json exists, this machine only collects and sends its records to the
// monitoring server named there; it has no web GUI or database of its own.
public class AgentConfig
{
    public static readonly string DataDir = AppPaths.DataDir;
    public static readonly string FilePath = Path.Combine(DataDir, "agent.json");

    public string ServerUrl { get; set; } = "";
    public string Fingerprint { get; set; } = "";
    public string Key { get; set; } = ""; // "<agent id>.<secret>"

    public static bool Exists => File.Exists(FilePath);

    public static AgentConfig Load() =>
        JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(FilePath))
            ?? throw new InvalidOperationException($"{FilePath} is empty.");

    // The key is a credential: the file is readable by SYSTEM and Administrators only (root on Linux)
    public void Save()
    {
#if LINUX_AGENT
        Directory.CreateDirectory(DataDir);
        File.Delete(FilePath);
        using var writer = new StreamWriter(new FileStream(FilePath, new FileStreamOptions
        {
            Mode = FileMode.CreateNew, Access = FileAccess.Write,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        }));
        writer.Write(JsonSerializer.Serialize(this));
#else
        SecretStore.WriteProtected(FilePath, JsonSerializer.Serialize(this));
#endif
    }

    // HTTPS that trusts exactly the monitoring server's certificate (pinned by fingerprint)
    public static HttpClient CreateClient(string serverUrl, string fingerprint) => new(new SocketsHttpHandler
    {
        SslOptions = new SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = (_, cert, _, _) =>
                cert != null && string.Equals(Convert.ToHexString(SHA256.HashData(cert.GetRawCertData())),
                    fingerprint, StringComparison.OrdinalIgnoreCase),
        },
        PooledConnectionLifetime = TimeSpan.FromMinutes(10),
    })
    {
        BaseAddress = new Uri(serverUrl.TrimEnd('/') + "/"),
        Timeout = TimeSpan.FromSeconds(60),
    };
}

// What differs between the Windows and the Linux agent
public interface IAgentPlatform
{
    // Whether file access auditing is on, for the Agents list (null when unknown)
    bool? AuditOk();

    // Runs a job from the monitoring server (applySacl, removeSacl, scan) and returns its answer
    JsonObject RunJob(AgentJob job, CancellationToken ct);
}

// "1.3.0" from the informational version ("1.3.0+<commit>"); "0.0.0" for local builds
public static class AppInfo
{
    public static readonly string Version =
        (typeof(AppInfo).Assembly
            .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .FirstOrDefault() as System.Reflection.AssemblyInformationalVersionAttribute)?.InformationalVersion
            .Split('+')[0] ?? "0.0.0";

    // "Windows Server 2022 Standard" or "Ubuntu 24.04 LTS", shown in the Agents list
    public static readonly string OsName = ReadOsName();

    private static string ReadOsName()
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                var name = key?.GetValue("ProductName") as string ?? "Windows";
                // Windows 11 still says "Windows 10" there
                return Environment.OSVersion.Version.Build >= 22000 && name.StartsWith("Windows 10")
                    ? "Windows 11" + name["Windows 10".Length..]
                    : name;
            }
            var pretty = File.ReadLines("/etc/os-release").FirstOrDefault(l => l.StartsWith("PRETTY_NAME="));
            return pretty != null ? pretty["PRETTY_NAME=".Length..].Trim('"') : "Linux";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return OperatingSystem.IsWindows() ? "Windows" : "Linux";
        }
    }
}

// "MonitoredPaths" in settings.json: plain strings (old format, all types) or { path, eventTypes }
public static class MonitoredPathList
{
    public static readonly string[] DefaultEventTypes = ["Read", "Write", "Delete"];

    public static List<(string Path, string[] EventTypes)> Parse(JsonObject root)
    {
        var list = new List<(string, string[])>();
        if (root["MonitoredPaths"] is not JsonArray arr) return list;
        foreach (var el in arr)
        {
            if (el is JsonValue v && v.TryGetValue<string>(out var p))
            {
                if (!string.IsNullOrEmpty(p)) list.Add((p, DefaultEventTypes));
            }
            else if (el is JsonObject o && o["path"] is JsonValue pv && pv.TryGetValue<string>(out var path)
                     && !string.IsNullOrEmpty(path))
            {
                var types = o["eventTypes"] is JsonArray ta
                    ? ta.Select(t => t is JsonValue tv && tv.TryGetValue<string>(out var ts) ? ts : "")
                        .Where(t => t.Length > 0).ToArray()
                    : DefaultEventTypes;
                list.Add((path, types));
            }
        }
        return list;
    }
}

// Batches waiting to be sent, one JSON file each, named by sequence number. Written before the
// collector moves on, so nothing is lost while the monitoring server is unreachable.
public class AgentOutbox
{
    public const long MaxBytes = 2L * 1024 * 1024 * 1024;

    private readonly string _dir;
    private readonly string _seqFile;
    private readonly string _positionFile;
    private readonly object _lock = new();
    private long _nextSeq;
    private long _bytes;

    public AgentOutbox(string? dataDir = null)
    {
        var root = dataDir ?? AgentConfig.DataDir;
        _dir = Path.Combine(root, "outbox");
        _seqFile = Path.Combine(root, "agent-seq.txt");
        _positionFile = Path.Combine(root, "agent-position.txt");
        Directory.CreateDirectory(_dir);

        var files = Directory.GetFiles(_dir, "*.json");
        _bytes = files.Sum(f => new FileInfo(f).Length);
        // A crash between writing a batch and the sequence file leaves the batch as the newest
        var newestFile = files.Select(f => long.TryParse(Path.GetFileNameWithoutExtension(f), out var n) ? n : 0)
            .DefaultIfEmpty(0).Max();
        _nextSeq = Math.Max(ReadLong(_seqFile), newestFile) + 1;
    }

    public event Action? Added;

    // Where the collector got to: a Security log record id (Windows) or a journal cursor (Linux)
    public string Position => File.Exists(_positionFile) ? File.ReadAllText(_positionFile).Trim() : "";

    // False when the outbox is full (the monitoring server has been unreachable for long)
    public bool Add(AgentBatch batch)
    {
        lock (_lock)
        {
            if (_bytes > MaxBytes) return false;
            batch.Seq = _nextSeq;
            var bytes = JsonSerializer.SerializeToUtf8Bytes(batch);
            var path = Path.Combine(_dir, $"{batch.Seq:D16}.json");
            File.WriteAllBytes(path + ".tmp", bytes);
            File.Move(path + ".tmp", path);
            File.WriteAllText(_seqFile, batch.Seq.ToString());
            _nextSeq++;
            _bytes += bytes.Length;
        }
        Added?.Invoke();
        return true;
    }

    public void SavePosition(string position)
    {
        File.WriteAllText(_positionFile + ".tmp", position);
        File.Move(_positionFile + ".tmp", _positionFile, overwrite: true);
    }

    public (string Path, AgentBatch Batch)? Oldest()
    {
        var path = Directory.GetFiles(_dir, "*.json").Order(StringComparer.Ordinal).FirstOrDefault();
        if (path == null) return null;
        var batch = JsonSerializer.Deserialize<AgentBatch>(File.ReadAllBytes(path));
        return batch == null ? null : (path, batch);
    }

    public void Remove(string path)
    {
        var file = new FileInfo(path);
        if (!file.Exists) return; // already removed (for example by a second agent process)
        var length = file.Length;
        File.Delete(path);
        lock (_lock) _bytes -= length;
    }

    public int Count => Directory.GetFiles(_dir, "*.json").Length;

    private static long ReadLong(string path) =>
        File.Exists(path) && long.TryParse(File.ReadAllText(path).Trim(), out var n) ? n : 0;
}

// Where a collector hands what it found: the local database on a monitoring server
// (LocalRecordSink), the outbox on an agent (RemoteRecordSink)
public interface IRecordSink
{
    // Saves the records together with the position they were collected up to (Security log record
    // id, or journal cursor on Linux), so that neither is saved without the other. False when the
    // batch had to be dropped.
    Task<bool> SaveAsync(IReadOnlyList<FileAccessMonitor.Models.AccessRecord> batch, string position);

    // Position to resume after ("" = start with live events)
    Task<string> LoadPositionAsync();

    // Recording was interrupted (log overwritten or cleared): log it and notify
    Task ReportGapAsync(string auditDetail, string messageKey, params object[] args);
}

// The agent's record sink: puts batches in the outbox for AgentSender to deliver
public class RemoteRecordSink(AgentOutbox outbox, ILogger<RemoteRecordSink> logger) : IRecordSink
{
    public Task<bool> SaveAsync(IReadOnlyList<FileAccessMonitor.Models.AccessRecord> batch, string position)
    {
        try
        {
            if (batch.Count > 0 && !outbox.Add(new AgentBatch { Records = batch.Select(AgentRecord.From).ToList() }))
            {
                logger.LogError("The outbox is full ({Max} bytes); dropping {Count} records. Is the monitoring server reachable?",
                    AgentOutbox.MaxBytes, batch.Count);
                return Task.FromResult(false);
            }
            outbox.SavePosition(position);
            return Task.FromResult(true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogError(ex, "Could not write {Count} records to the outbox.", batch.Count);
            return Task.FromResult(false);
        }
    }

    public Task<string> LoadPositionAsync() => Task.FromResult(outbox.Position);

    public Task ReportGapAsync(string auditDetail, string messageKey, params object[] args)
    {
        outbox.Add(new AgentBatch
        {
            Gap = new AgentGap
            {
                AuditDetail = auditDetail, MessageKey = messageKey,
                Args = args.Select(a => Convert.ToString(a, System.Globalization.CultureInfo.InvariantCulture) ?? "").ToList(),
            },
        });
        return Task.CompletedTask;
    }
}

// Sends the outbox to the monitoring server in order, retrying with growing waits while it is
// unreachable, and says hello once a minute when there is nothing to send.
public class AgentSender(AgentOutbox outbox, AgentConfig config, IAgentPlatform platform, ILogger<AgentSender> logger)
    : BackgroundService
{
    private static readonly TimeSpan HeartbeatInterval = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var client = AgentConfig.CreateClient(config.ServerUrl, config.Fingerprint);
        client.DefaultRequestHeaders.Authorization = new("Bearer", config.Key);
        var wake = new SemaphoreSlim(0);
        outbox.Added += () => { if (wake.CurrentCount == 0) wake.Release(); };

        var backoff = TimeSpan.FromSeconds(5);
        var lastContact = DateTime.MinValue;
        // What the monitoring server understands (see AgentProtocol.ForServer): assumed to be the old
        // protocol until a heartbeat reply says otherwise, so a heartbeat goes before the first batch
        var serverProtocol = 1;
        var protocolKnown = false;
        var lastHeartbeat = DateTime.MinValue;
        var failing = false;
        logger.LogInformation("Agent sending to {Server} ({Count} batches waiting).", config.ServerUrl, outbox.Count);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // An old server is asked again now and then, so that it is noticed when it has been upgraded
                var heartbeatFirst = !protocolKnown || (serverProtocol < AgentProtocol.Version && DateTime.UtcNow - lastHeartbeat >= HeartbeatInterval);
                if (!heartbeatFirst && outbox.Oldest() is { } next)
                {
                    using var request = new HttpRequestMessage(HttpMethod.Post, "api/agent/batch")
                    {
                        Content = JsonContent.Create(AgentProtocol.ForServer(next.Batch, serverProtocol)),
                    };
                    request.Headers.Add("X-Agent-Outbox", (outbox.Count - 1).ToString()); // still waiting after this one
                    using var response = await client.SendAsync(request, stoppingToken);
                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                        throw new AgentRejectedException();
                    response.EnsureSuccessStatusCode();
                    outbox.Remove(next.Path);
                }
                else if (heartbeatFirst || DateTime.UtcNow - lastContact >= HeartbeatInterval)
                {
                    using var response = await client.PostAsJsonAsync("api/agent/heartbeat",
                        new HeartbeatRequest(AppInfo.Version, outbox.Count, platform.AuditOk(), AppInfo.OsName), stoppingToken);
                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                        throw new AgentRejectedException();
                    response.EnsureSuccessStatusCode();
                    var reply = await response.Content.ReadFromJsonAsync<JsonElement>(stoppingToken);
                    serverProtocol = reply.TryGetProperty("protocol", out var p) && p.TryGetInt32(out var pv) ? pv : 1;
                    protocolKnown = true;
                    lastHeartbeat = DateTime.UtcNow;
                    if (reply.TryGetProperty("configVersion", out var v) && v.GetInt32() != AgentSettingsSync.AppliedVersion)
                        await AgentSettingsSync.FetchAsync(client, logger, stoppingToken);
                }
                else
                {
                    await wake.WaitAsync(TimeSpan.FromSeconds(10), stoppingToken);
                    continue;
                }

                lastContact = DateTime.UtcNow;
                backoff = TimeSpan.FromSeconds(5);
                if (failing) logger.LogInformation("Connected to the monitoring server again.");
                failing = false;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                var rejected = ex is AgentRejectedException;
                if (!failing || rejected)
                    logger.LogWarning(rejected ? null : ex, rejected
                        ? "The monitoring server does not accept this agent (disabled, or removed: register it again). Retrying in 5 minutes."
                        : "Cannot reach the monitoring server at {Server}; records wait in the outbox.", config.ServerUrl);
                failing = true;
                var wait = rejected ? MaxBackoff : backoff;
                backoff = TimeSpan.FromTicks(Math.Min(backoff.Ticks * 2, MaxBackoff.Ticks));
                try { await Task.Delay(wait, stoppingToken); } catch (OperationCanceledException) { break; }
            }
        }
    }

    private sealed class AgentRejectedException : Exception;
}

// Monitored folders and recording rules are set on the monitoring server; the agent copies them
// into its own settings.json, which the collector already watches.
public static class AgentSettingsSync
{
    private static readonly string VersionFile = Path.Combine(AgentConfig.DataDir, "agent-config-version.txt");

    // -1 until the first sync, so an agent always takes the server's settings once
    public static int AppliedVersion =>
        File.Exists(VersionFile) && int.TryParse(File.ReadAllText(VersionFile).Trim(), out var v) ? v : -1;

    public static async Task FetchAsync(HttpClient client, ILogger logger, CancellationToken ct)
    {
        var reply = await client.GetFromJsonAsync<JsonObject>("api/agent/config", ct)
            ?? throw new InvalidOperationException("Empty configuration from the monitoring server.");
        var config = reply["config"] as JsonObject ?? [];
        SettingsStore.Update(root =>
        {
            root["MonitoredPaths"] = config["MonitoredPaths"]?.DeepClone() ?? new JsonArray();
            if (config[RecordingSettings.SettingsKey] is { } recording)
                root[RecordingSettings.SettingsKey] = recording.DeepClone();
            else
                root.Remove(RecordingSettings.SettingsKey);
        });
        var version = reply["version"]?.GetValue<int>() ?? 0;
        File.WriteAllText(VersionFile, version.ToString());
        logger.LogInformation("Applied settings version {Version} from the monitoring server.", version);
    }
}

// Does work for the monitoring server's GUI on this server: checks folders, sets up or removes
// their auditing, lists files for the Unused Files tab. Waits for jobs with a long poll, so it
// answers in about a second while the connection still goes from agent to server.
public class AgentJobRunner(AgentConfig config, IAgentPlatform platform, ILogger<AgentJobRunner> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var client = AgentConfig.CreateClient(config.ServerUrl, config.Fingerprint);
        client.DefaultRequestHeaders.Authorization = new("Bearer", config.Key);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var response = await client.GetAsync("api/agent/jobs", stoppingToken);
                if (response.StatusCode == System.Net.HttpStatusCode.NoContent) continue;
                response.EnsureSuccessStatusCode();
                var job = await response.Content.ReadFromJsonAsync<AgentJob>(stoppingToken);
                if (job == null) continue;

                JsonObject result;
                try { result = await Task.Run(() => platform.RunJob(job, stoppingToken), stoppingToken); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogWarning(ex, "Job {Type} failed.", job.Type);
                    result = new JsonObject { ["error"] = ex.Message };
                }
                using var answer = await client.PostAsJsonAsync($"api/agent/jobs/{job.Id}", result, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception)
            {
                // The sender logs connection problems; just wait before asking again
                try { await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken); } catch (OperationCanceledException) { break; }
            }
        }
    }

    // The job's folder ("path", or "folder" for a scan)
    public static string PathOf(AgentJob job) =>
        job.Args["path"]?.GetValue<string>() ?? job.Args["folder"]?.GetValue<string>() ?? "";

    // The answer to a "scan" job: files as [path, size, modified (UTC ticks)], which keeps a large listing compact
    public static JsonObject ScanResult(IEnumerable<(string Path, long Size, DateTime ModifiedUtc)> files, int scanned, bool truncated) => new()
    {
        ["exists"] = true, ["scanned"] = scanned, ["truncated"] = truncated,
        ["files"] = new JsonArray(files.Select(f => (JsonNode)new JsonArray(f.Path, f.Size, f.ModifiedUtc.Ticks)).ToArray()),
    };

    public static JsonObject AuditResult(int count, List<string> errors) => new()
    {
        ["exists"] = true, ["count"] = count,
        ["errors"] = new JsonArray(errors.Take(100).Select(e => (JsonNode)JsonValue.Create(e)!).ToArray()),
    };
}

// "<exe> enroll <connection string>" / "unenroll"
public static class AgentCommands
{
    public static async Task<int> RunCommandAsync(string[] args, string exeName, string restartCommand)
    {
        if (args[0] == "unenroll")
        {
            if (AgentConfig.Exists) File.Delete(AgentConfig.FilePath);
            Console.WriteLine($"This machine is no longer an agent. {restartCommand}");
            return 0;
        }

        if (args.Length < 2 || AgentConnection.Parse(args[1]) is not { } connection)
        {
            Console.Error.WriteLine($"Usage: {exeName} enroll <connection string from the monitoring server>");
            return 2;
        }
        try
        {
            using var client = AgentConfig.CreateClient(connection.Url, connection.Fingerprint);
            using var response = await client.PostAsJsonAsync("api/agent/enroll",
                new EnrollRequest(connection.Code, Environment.MachineName, AppInfo.Version));
            if (!response.IsSuccessStatusCode)
            {
                Console.Error.WriteLine($"Registration failed ({(int)response.StatusCode}): {await response.Content.ReadAsStringAsync()}");
                return 1;
            }
            var result = await response.Content.ReadFromJsonAsync<EnrollResponse>();
            new AgentConfig { ServerUrl = connection.Url, Fingerprint = connection.Fingerprint, Key = result!.Key }.Save();
            Console.WriteLine($"Registered with {connection.Url} as {Environment.MachineName}. {restartCommand}");
            return 0;
        }
        catch (HttpRequestException ex)
        {
            Console.Error.WriteLine($"Cannot reach {connection.Url}: {ex.Message}");
            Console.Error.WriteLine("Check the address, that the agent port is open in the monitoring server's firewall, and the certificate fingerprint.");
            return 1;
        }
    }
}
