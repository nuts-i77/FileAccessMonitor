using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using FileAccessMonitor.Models;
using Serilog;

namespace FileAccessMonitor.Services;

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

    // The key is a credential: the file is readable by SYSTEM and Administrators only
    public void Save() => SecretStore.WriteProtected(FilePath, JsonSerializer.Serialize(this));

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

    public long Position => ReadLong(_positionFile);

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

    public void SavePosition(long lastRecordId) => File.WriteAllText(_positionFile, lastRecordId.ToString());

    public (string Path, AgentBatch Batch)? Oldest()
    {
        var path = Directory.GetFiles(_dir, "*.json").Order(StringComparer.Ordinal).FirstOrDefault();
        if (path == null) return null;
        var batch = JsonSerializer.Deserialize<AgentBatch>(File.ReadAllBytes(path));
        return batch == null ? null : (path, batch);
    }

    public void Remove(string path)
    {
        var length = new FileInfo(path).Length;
        File.Delete(path);
        lock (_lock) _bytes -= length;
    }

    public int Count => Directory.GetFiles(_dir, "*.json").Length;

    private static long ReadLong(string path) =>
        File.Exists(path) && long.TryParse(File.ReadAllText(path).Trim(), out var n) ? n : 0;
}

// The agent's record sink: puts batches in the outbox for AgentSender to deliver
public class RemoteRecordSink(AgentOutbox outbox, ILogger<RemoteRecordSink> logger) : IRecordSink
{
    public Task<bool> SaveAsync(IReadOnlyList<AccessRecord> batch, long lastRecordId)
    {
        try
        {
            if (batch.Count > 0 && !outbox.Add(new AgentBatch { Records = batch.Select(AgentRecord.From).ToList() }))
            {
                logger.LogError("The outbox is full ({Max} bytes); dropping {Count} records. Is the monitoring server reachable?",
                    AgentOutbox.MaxBytes, batch.Count);
                return Task.FromResult(false);
            }
            outbox.SavePosition(lastRecordId);
            return Task.FromResult(true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogError(ex, "Could not write {Count} records to the outbox.", batch.Count);
            return Task.FromResult(false);
        }
    }

    public Task<long> LoadPositionAsync() => Task.FromResult(outbox.Position);

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
public class AgentSender(AgentOutbox outbox, AgentConfig config, ILogger<AgentSender> logger) : BackgroundService
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
        var failing = false;
        logger.LogInformation("Agent sending to {Server} ({Count} batches waiting).", config.ServerUrl, outbox.Count);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (outbox.Oldest() is { } next)
                {
                    using var request = new HttpRequestMessage(HttpMethod.Post, "api/agent/batch")
                    {
                        Content = JsonContent.Create(next.Batch),
                    };
                    request.Headers.Add("X-Agent-Outbox", (outbox.Count - 1).ToString()); // still waiting after this one
                    using var response = await client.SendAsync(request, stoppingToken);
                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                        throw new AgentRejectedException();
                    response.EnsureSuccessStatusCode();
                    outbox.Remove(next.Path);
                }
                else if (DateTime.UtcNow - lastContact >= HeartbeatInterval)
                {
                    using var response = await client.PostAsJsonAsync("api/agent/heartbeat",
                        new HeartbeatRequest(Controllers.SettingsController.AppVersion, outbox.Count,
                            SaclManagerService.IsFileSystemAuditOn()), stoppingToken);
                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                        throw new AgentRejectedException();
                    response.EnsureSuccessStatusCode();
                    var reply = await response.Content.ReadFromJsonAsync<JsonElement>(stoppingToken);
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

    public static async Task FetchAsync(HttpClient client, Microsoft.Extensions.Logging.ILogger logger, CancellationToken ct)
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

// Does work for the monitoring server's GUI on this server: checks folders, sets or removes their
// SACL, lists files for the Unused Files tab. Waits for jobs with a long poll, so it answers in
// about a second while the connection still goes from agent to server.
public class AgentJobRunner(AgentConfig config, SaclManagerService sacl, ILogger<AgentJobRunner> logger) : BackgroundService
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
                try { result = await Task.Run(() => Run(job, stoppingToken), stoppingToken); }
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

    private JsonObject Run(AgentJob job, CancellationToken ct)
    {
        var path = job.Args["path"]?.GetValue<string>() ?? job.Args["folder"]?.GetValue<string>() ?? "";
        if (!Directory.Exists(path)) return new JsonObject { ["exists"] = false };
        logger.LogInformation("Running {Type} for {Path} as asked by the monitoring server.", job.Type, path);

        switch (job.Type)
        {
            case "applySacl":
            {
                sacl.EnableAuditPolicy();
                var (count, errors) = sacl.ApplySacl(path);
                return SaclResult(count, errors);
            }
            case "removeSacl":
            {
                var (count, errors) = sacl.RemoveSacl(path);
                return SaclResult(count, errors);
            }
            case "scan":
            {
                var (files, scanned, truncated) = Controllers.UnusedFilesController.Scan(
                    path, new HashSet<string>(), new RecordingRules(RecordingSettings.Load()), ct);
                return new JsonObject
                {
                    ["exists"] = true, ["scanned"] = scanned, ["truncated"] = truncated,
                    // [path, size, modified (UTC ticks)] keeps a large listing compact
                    ["files"] = new JsonArray(files.Select(f => (JsonNode)new JsonArray(f.Path, f.Size, f.ModifiedUtc.Ticks)).ToArray()),
                };
            }
            default:
                return new JsonObject { ["error"] = $"Unknown job {job.Type}; update the agent." };
        }
    }

    private static JsonObject SaclResult(int count, List<string> errors) => new()
    {
        ["exists"] = true, ["count"] = count,
        ["errors"] = new JsonArray(errors.Take(100).Select(e => (JsonNode)JsonValue.Create(e)!).ToArray()),
    };
}

public static class AgentHost
{
    // "FileAccessMonitor.exe enroll <connection string>" / "unenroll"
    public static async Task<int> RunCommandAsync(string[] args)
    {
        if (args[0] == "unenroll")
        {
            if (AgentConfig.Exists) File.Delete(AgentConfig.FilePath);
            Console.WriteLine("This machine is no longer an agent. Restart the service to run standalone.");
            return 0;
        }

        if (args.Length < 2 || AgentConnection.Parse(args[1]) is not { } connection)
        {
            Console.Error.WriteLine("Usage: FileAccessMonitor.exe enroll <connection string from the monitoring server>");
            return 2;
        }
        try
        {
            using var client = AgentConfig.CreateClient(connection.Url, connection.Fingerprint);
            using var response = await client.PostAsJsonAsync("api/agent/enroll",
                new EnrollRequest(connection.Code, Environment.MachineName, Controllers.SettingsController.AppVersion));
            if (!response.IsSuccessStatusCode)
            {
                Console.Error.WriteLine($"Registration failed ({(int)response.StatusCode}): {await response.Content.ReadAsStringAsync()}");
                return 1;
            }
            var result = await response.Content.ReadFromJsonAsync<EnrollResponse>();
            new AgentConfig { ServerUrl = connection.Url, Fingerprint = connection.Fingerprint, Key = result!.Key }.Save();
            Console.WriteLine($"Registered with {connection.Url} as {Environment.MachineName}. Restart the service to start sending.");
            return 0;
        }
        catch (HttpRequestException ex)
        {
            Console.Error.WriteLine($"Cannot reach {connection.Url}: {ex.Message}");
            Console.Error.WriteLine("Check the address, that the agent port is open in the monitoring server's firewall, and the certificate fingerprint.");
            return 1;
        }
    }

    public static async Task RunAsync(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddSerilog();
        builder.Configuration.AddJsonFile(Path.Combine(AgentConfig.DataDir, "settings.json"), optional: true, reloadOnChange: true);
        builder.Services.AddWindowsService(options => options.ServiceName = "FileAccessMonitor");

        var config = AgentConfig.Load();
        builder.Services.AddSingleton(config);
        builder.Services.AddSingleton(new AgentOutbox());
        builder.Services.AddSingleton<DnsResolverService>();
        builder.Services.AddSingleton<IRecordSink, RemoteRecordSink>();
        builder.Services.AddSingleton<SaclManagerService>();
        builder.Services.AddHostedService<AgentSender>();
        builder.Services.AddHostedService<AgentJobRunner>();
        builder.Services.AddHostedService<EventLogCollectorService>();

        var host = builder.Build();
        host.Services.GetRequiredService<DnsResolverService>().SetDnsServer(builder.Configuration["DnsServer"]);
        Log.Information("Starting as an agent of {Server}.", config.ServerUrl);
        await host.RunAsync();
    }
}
