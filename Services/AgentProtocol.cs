using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FileAccessMonitor.Models;

namespace FileAccessMonitor.Services;

// What an agent sends: one outbox item. Seq increases by one per item on each agent, so the
// server can ignore an item it already saved (resent after a lost response).
public class AgentBatch
{
    public long Seq { get; set; }
    public List<AgentRecord>? Records { get; set; }
    public AgentGap? Gap { get; set; }
}

public class AgentRecord
{
    public string FilePath { get; set; } = "";
    public string FileName { get; set; } = "";
    public string FolderPath { get; set; } = "";
    public string UserName { get; set; } = "";
    public string AccessType { get; set; } = "";
    public DateTime AccessTime { get; set; }
    public string? ClientIp { get; set; }
    public string? ClientMachine { get; set; }
    public bool IsFolder { get; set; }
    // From 1.9 (protocol 2); older agents leave them out and older servers ignore them
    public bool Denied { get; set; }
    public string? NewPath { get; set; }
    public string? Detail { get; set; }
    // From 1.10.2: a Permission record made while its file was created; older agents omit it, older servers ignore it
    public bool AtCreation { get; set; }

    public static AgentRecord From(AccessRecord r) => new()
    {
        FilePath = r.FilePath, FileName = r.FileName, FolderPath = r.FolderPath, UserName = r.UserName,
        AccessType = r.AccessType, AccessTime = r.AccessTime, ClientIp = r.ClientIp,
        ClientMachine = r.ClientMachine, IsFolder = r.IsFolder,
        Denied = r.Denied, NewPath = r.NewPath, Detail = r.Detail, AtCreation = r.AtCreation,
    };

    // The server name comes from the agent's registration, not from what the agent says
    public AccessRecord ToRecord(string serverName) => new()
    {
        FilePath = Limit(FilePath, 2000), FileName = Limit(FileName, 500), FolderPath = Limit(FolderPath, 2000),
        UserName = Limit(UserName, 200), AccessType = Limit(AccessType, 20),
        AccessTime = DateTime.SpecifyKind(AccessTime, DateTimeKind.Utc),
        ClientIp = ClientIp == null ? null : Limit(ClientIp, 100),
        ClientMachine = ClientMachine == null ? null : Limit(ClientMachine, 200),
        IsFolder = IsFolder, ServerName = serverName,
        Denied = Denied,
        NewPath = NewPath == null ? null : Limit(NewPath, 2000),
        Detail = Detail == null ? null : Limit(Detail, 2000),
        AtCreation = AtCreation,
    };

    private static string Limit(string s, int max) => s.Length <= max ? s : s[..max];
}

// Recording was interrupted on the agent (see IRecordSink.ReportGapAsync)
public class AgentGap
{
    public string AuditDetail { get; set; } = "";
    public string MessageKey { get; set; } = "";
    public List<string> Args { get; set; } = [];
}

// 2 (1.9): records may carry Denied, NewPath, Detail and the types Create and Permission. The
// server announces it in the heartbeat reply ("protocol"); an agent sends those only to a server
// that announced 2.
public static class AgentProtocol
{
    public const int Version = 2;

    // What a server that announced `protocol` understands. Protocol 1 (1.8 and older, or no answer
    // yet) knows neither refused attempts nor Create/Permission, and would store them as ordinary
    // accesses; so for it denied and Permission records are left out, Create is sent as Write and
    // NewPath/Detail are dropped. The batch (the outbox file) is not changed, so a server that is
    // upgraded later still gets everything that was waiting.
    public static AgentBatch ForServer(AgentBatch batch, int protocol)
    {
        if (protocol >= 2 || batch.Records == null) return batch;
        var records = new List<AgentRecord>(batch.Records.Count);
        foreach (var r in batch.Records)
        {
            if (r.Denied || r.AccessType == AccessTypes.Permission) continue;
            records.Add(new AgentRecord
            {
                FilePath = r.FilePath, FileName = r.FileName, FolderPath = r.FolderPath, UserName = r.UserName,
                AccessType = r.AccessType == AccessTypes.Create ? AccessTypes.Write : r.AccessType,
                AccessTime = r.AccessTime, ClientIp = r.ClientIp, ClientMachine = r.ClientMachine, IsFolder = r.IsFolder,
            });
        }
        return new AgentBatch { Seq = batch.Seq, Records = records, Gap = batch.Gap };
    }
}

// Something an agent does on its own server for the GUI: check a folder, set up or remove its
// auditing, list its files
public record AgentJob(string Id, string Type, System.Text.Json.Nodes.JsonObject Args);

public record EnrollRequest(string Code, string Name, string? Version);
public record EnrollResponse(string AgentId, string Key);
// OutboxCount: batches waiting on the agent; AuditPolicyOk: whether file access auditing is on there
// (File System auditing on Windows, Samba's audit module on Linux); Os: the agent's operating system
// OutboxFull / OutboxBytes (from 1.11): the outbox reached its limit and collection is paused; its size.
// Older agents leave them out (null = not full), older servers ignore them.
public record HeartbeatRequest(string? Version, int? OutboxCount = null, bool? AuditPolicyOk = null, string? Os = null,
    bool? OutboxFull = null, long? OutboxBytes = null);

// Everything an agent needs to register, in one string an Admin copies from the GUI:
// the agent endpoint URL, the SHA-256 fingerprint of its certificate, and a one-time code.
public record AgentConnection(string Url, string Fingerprint, string Code)
{
    private const string Prefix = "FAM1.";

    public override string ToString() =>
        Prefix + Base64Url(JsonSerializer.SerializeToUtf8Bytes(new { u = Url, f = Fingerprint, c = Code }));

    public static AgentConnection? Parse(string text)
    {
        text = text.Trim();
        if (!text.StartsWith(Prefix, StringComparison.Ordinal)) return null;
        try
        {
            var b64 = text[Prefix.Length..].Replace('-', '+').Replace('_', '/');
            b64 = b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '=');
            using var doc = JsonDocument.Parse(Convert.FromBase64String(b64));
            var root = doc.RootElement;
            var c = new AgentConnection(root.GetProperty("u").GetString()!, root.GetProperty("f").GetString()!,
                root.GetProperty("c").GetString()!);
            return c.Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? c : null;
        }
        catch (Exception ex) when (ex is FormatException or JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return null;
        }
    }

    private static string Base64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

public static class AgentSecrets
{
    public static string NewSecret() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string Hash(string secret) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));

    public static bool Matches(string secret, string hash) =>
        CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Hash(secret)), Encoding.ASCII.GetBytes(hash));

    // Certificate fingerprint as pinned by agents (SHA-256 of the DER bytes, upper-case hex)
    public static string Fingerprint(System.Security.Cryptography.X509Certificates.X509Certificate2 cert) =>
        Convert.ToHexString(SHA256.HashData(cert.RawData));
}
