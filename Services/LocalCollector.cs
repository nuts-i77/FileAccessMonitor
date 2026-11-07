using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace FileAccessMonitor.Services;

// The web part (an unprivileged account) and the collector (SYSTEM / root, "FileAccessMonitor collector")
// are two processes of the same program. The collector is a built-in agent of this server: it reads the
// Security log (Samba's audit lines on Linux), sets up auditing and scans folders, and talks to the
// server's agent port over loopback. It needs no registration: it keeps a random secret in the
// collector\ folder (readable by SYSTEM / root only) and publishes the secret's hash in
// collector\key.hash, which the web part can read but not write. The web part accepts the credential
// "local.<secret>" as the pseudo-agent below; that agent is not a row of the Agents table.
public static class LocalCollector
{
    // The reserved agent id (real agents have random 32-character ids)
    public const string AgentId = "local";
    public const string SecretFileName = "key.secret";
    public const string KeyHashFileName = "key.hash";

    // The batch sequence the web part has saved from the collector, with the key it belongs to
    // (a new key means a new collector state, which numbers its batches from 1 again)
    public const string SeqStateKey = "LocalCollectorSeq";

    public static string Folder => Path.Combine(AppPaths.BaseDataDir, AppPaths.CollectorFolderName);

    // The hash the collector published, or null when it never ran (then there is no local collector)
    public static string? ReadKeyHash(string? folder = null)
    {
        try
        {
            var file = Path.Combine(folder ?? Folder, KeyHashFileName);
            if (!File.Exists(file)) return null;
            var hash = File.ReadAllText(file).Trim();
            return hash.Length == 64 && hash.All(Uri.IsHexDigit) ? hash : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    // Whether the secret of a credential "local.<secret>" is the collector's
    public static bool Matches(string secret, string? folder = null) =>
        ReadKeyHash(folder) is { } hash && AgentSecrets.Matches(secret, hash);

    // The pseudo-agent the web part answers as (never stored)
    public static FileAccessMonitor.Models.Agent PseudoAgent() => new()
    {
        Id = AgentId, Name = ServerConfigService.LocalName, KeyHash = "", CreatedAt = DateTime.UtcNow,
    };

    // ---- collector side

    // The collector's folder: administrators only (Windows: SYSTEM and Administrators; Linux: root-owned,
    // others may only look up key.hash inside it). Logs and the outbox are not for other accounts either.
    public static void EnsureFolder(string? folder = null)
    {
        folder ??= Folder;
        if (OperatingSystem.IsWindows())
        {
            var security = new System.Security.AccessControl.DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            // SYSTEM and Administrators; the account running the collector too (SYSTEM in the service; a manual run as a
            // standard user must not lock itself out)
            var sids = new List<System.Security.Principal.SecurityIdentifier>
            {
                new(System.Security.Principal.WellKnownSidType.LocalSystemSid, null),
                new(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null),
            };
            if (System.Security.Principal.WindowsIdentity.GetCurrent().User is { } self && !sids.Contains(self)) sids.Add(self);
            foreach (var sid in sids)
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    sid,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
            new DirectoryInfo(folder).Create(security);
            new DirectoryInfo(folder).SetAccessControl(security); // also when it existed (an upgrade, a copy of the data folder)
            return;
        }
        Directory.CreateDirectory(folder, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        File.SetUnixFileMode(folder, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        foreach (var sub in new[] { "logs", "outbox" })
            Directory.CreateDirectory(Path.Combine(folder, sub), UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    // The collector's secret: made on the first start and kept; the hash file is written again when it
    // is missing or does not belong to the secret (it was lost, or an old copy came back)
    public static string GetOrCreateSecret(string? folder = null)
    {
        folder ??= Folder;
        var secretFile = Path.Combine(folder, SecretFileName);
        string? secret = null;
        try { if (File.Exists(secretFile)) secret = File.ReadAllText(secretFile).Trim(); }
        catch (IOException) { }
        if (secret is not { Length: >= 32 })
        {
            secret = AgentSecrets.NewSecret();
            SecretStore.WriteProtected(secretFile, secret, SecretStore.Audience.Administrators);
        }
        if (ReadKeyHash(folder) != AgentSecrets.Hash(secret))
            SecretStore.WriteProtected(Path.Combine(folder, KeyHashFileName), AgentSecrets.Hash(secret),
                SecretStore.Audience.AdministratorsWebRead);
        return secret;
    }

    // ---- settings the collector copies (the same shape agents get)

    // Monitored folders and recording rules of this machine out of settings.json
    public static JsonObject ConfigFrom(JsonObject settings)
    {
        var config = new JsonObject
        {
            ["MonitoredPaths"] = settings["MonitoredPaths"]?.DeepClone() ?? new JsonArray(),
        };
        if (settings[RecordingSettings.SettingsKey] is { } recording)
            config[RecordingSettings.SettingsKey] = recording.DeepClone();
        return config;
    }

    // Changes whenever the config does (agents get a counter from the database; this one is derived)
    public static int ConfigVersion(JsonObject config) =>
        BitConverter.ToInt32(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(config.ToJsonString()))) & 0x7fffffff;
}

// What the web part knows about the collector service from its calls (kept in memory: a web restart
// forgets it until the collector's next call, a minute at most)
public class LocalCollectorState
{
    // Without a call for this long the collector counts as not connected (it calls at least once a minute)
    public static readonly TimeSpan ConnectedWindow = TimeSpan.FromMinutes(3);
    private readonly object _gate = new();
    private DateTime? _lastSeenUtc;
    private string? _version, _os;
    private bool? _auditPolicyOk;
    private int _outbox;

    public DateTime? LastSeenUtc { get { lock (_gate) return _lastSeenUtc; } }
    public string? Version { get { lock (_gate) return _version; } }
    public string? Os { get { lock (_gate) return _os; } }
    public bool? AuditPolicyOk { get { lock (_gate) return _auditPolicyOk; } }
    public int Outbox { get { lock (_gate) return _outbox; } }

    public bool IsConnected(DateTime nowUtc) => LastSeenUtc is { } seen && nowUtc - seen < ConnectedWindow;

    public void Touch(DateTime nowUtc) { lock (_gate) _lastSeenUtc = nowUtc; }

    public void SetOutbox(int waiting) { lock (_gate) _outbox = waiting; }

    public void Heartbeat(HeartbeatRequest req, DateTime nowUtc)
    {
        lock (_gate)
        {
            _lastSeenUtc = nowUtc;
            _version = req.Version;
            if (req.OutboxCount is { } count) _outbox = count;
            _auditPolicyOk = req.AuditPolicyOk;
            if (req.Os is { Length: > 0 } os) _os = os.Length <= 100 ? os : os[..100];
        }
    }

    // A job for the collector (setting up auditing, scanning a folder, ...), waiting for its answer.
    // Throws LocalCollectorException when it is not connected or does not answer in time.
    public async Task<JsonObject> RunJobAsync(AgentJobs jobs, string type, JsonObject args, TimeSpan timeout, CancellationToken ct)
    {
        if (!IsConnected(DateTime.UtcNow))
            throw new LocalCollectorException(StatusCodes.Status503ServiceUnavailable, Messages.Get("local.collectorOff"));
        JsonObject result;
        try
        {
            result = await jobs.RunAsync(LocalCollector.AgentId, type, args, timeout, ct);
        }
        catch (TimeoutException)
        {
            throw new LocalCollectorException(StatusCodes.Status504GatewayTimeout, Messages.Get("local.noAnswer"));
        }
        if (result["error"]?.GetValue<string>() is { } message)
            throw new LocalCollectorException(StatusCodes.Status400BadRequest, Messages.Get("local.jobFailed", message), message);
        return result;
    }
}

// The collector could not do a job: not connected (503), no answer (504), or it reported an error (400)
public class LocalCollectorException(int status, string message, string? reported = null) : Exception(message)
{
    public int Status => status;
    // The collector's own error text, when it reported one
    public string? Reported => reported;
}

// What the GUI shows about the collector service of this server
public record CollectorStatus(bool Connected, DateTime? LastSeen, bool? AuditPolicyOk, string? Version, int Outbox, string? Os)
{
    public static CollectorStatus From(LocalCollectorState state) =>
        new(state.IsConnected(DateTime.UtcNow), state.LastSeenUtc, state.AuditPolicyOk, state.Version, state.Outbox, state.Os);
}
