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

    public static AgentRecord From(AccessRecord r) => new()
    {
        FilePath = r.FilePath, FileName = r.FileName, FolderPath = r.FolderPath, UserName = r.UserName,
        AccessType = r.AccessType, AccessTime = r.AccessTime, ClientIp = r.ClientIp,
        ClientMachine = r.ClientMachine, IsFolder = r.IsFolder,
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

public record EnrollRequest(string Code, string Name, string? Version);
public record EnrollResponse(string AgentId, string Key);
// OutboxCount: batches waiting on the agent; AuditPolicyOk: whether File System auditing is on there
public record HeartbeatRequest(string? Version, int? OutboxCount = null, bool? AuditPolicyOk = null);

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
