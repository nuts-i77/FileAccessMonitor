namespace FileAccessMonitor.Services;

// The "permissions" agent job: read the permissions below a monitored folder. Shared by the
// server, the Windows agent and the Linux agent. Step-0 stub; completed by the permissions work.
public static class PermissionContract
{
    public const string JobType = "permissions";
}

public record PermissionScanOptions(int MaxFolders = 5000, int MaxFiles = 50000, int MaxDepth = 8,
    bool IncludeFiles = true, int TimeLimitSeconds = 300);
