using System.Text.Json.Nodes;

namespace FileAccessMonitor.Services;

// Stored permission scans: the GUI reads them, the scheduled report uses the last one of each folder
public interface IPermissionReports
{
    // The last stored scan of (server, root), or null. Never starts a scan.
    Task<StoredPermissionReport?> GetLastAsync(string server, string root, CancellationToken ct = default);
    Task<List<StoredPermissionReport>> ListAsync(CancellationToken ct = default);
    Task<StoredPermissionReport> ScanAsync(string server, string root, PermissionScanOptions options, CancellationToken ct);
}

// Server = the file server's name ("" = this machine); Result = the job result (see PermissionContract)
public class StoredPermissionReport
{
    public string Server { get; set; } = "";
    public string Root { get; set; } = "";
    public DateTime ScannedAt { get; set; }
    public string Os { get; set; } = "";
    public string? AgentVersion { get; set; }
    public JsonObject Result { get; set; } = [];
}

// A broad-access entry. Severity: high | medium
public record BroadRow(string Server, string Root, string Path, string Principal, string Kind,
    string Level, string Severity, bool InheritanceBroken);

public static class PermissionReportView
{
    // Broad-access rows of a scan; scope = null (everything) or the viewer's folders
    public static List<BroadRow> BroadRows(StoredPermissionReport report, IReadOnlyList<ScopeEntry>? scope) => [];
}

// Step-0 stub; filled in by the permissions work
public class PermissionReportService : IPermissionReports
{
    public Task<StoredPermissionReport?> GetLastAsync(string server, string root, CancellationToken ct = default) =>
        Task.FromResult<StoredPermissionReport?>(null);

    public Task<List<StoredPermissionReport>> ListAsync(CancellationToken ct = default) =>
        Task.FromResult(new List<StoredPermissionReport>());

    public Task<StoredPermissionReport> ScanAsync(string server, string root, PermissionScanOptions options, CancellationToken ct) =>
        throw new NotImplementedException();
}
