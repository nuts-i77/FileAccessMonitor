using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;

namespace FileAccessMonitor.Services;

public class SaclManagerService
{
    private readonly ILogger<SaclManagerService> _logger;

    public SaclManagerService(ILogger<SaclManagerService> logger)
    {
        _logger = logger;
    }

    public void EnableAuditPolicy()
    {
        try
        {
            var psi = new ProcessStartInfo("auditpol.exe",
                "/set /subcategory:\"{0CCE921D-69AE-11D9-BED3-505054503030}\" /success:enable /failure:enable")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(5000);
            _logger.LogInformation("Audit policy enabled.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to enable audit policy.");
        }
    }

    // Only rights that the collector turns into Read/Write/Delete records.
    // FileSystemRights.Read/Write would also audit ReadAttributes, ReadEA,
    // ReadPermissions, WriteAttributes etc., which floods the Security log
    // (e.g. media indexers scanning metadata) without producing any records.
    private const FileSystemRights AuditedRights =
        FileSystemRights.ReadData | FileSystemRights.WriteData |
        FileSystemRights.AppendData | FileSystemRights.Delete;

    // Replace (not merge) any existing Everyone audit entry, so re-applying
    // narrows SACLs that were set by older versions.
    private static void ReplaceAuditRule(FileSystemSecurity acl, FileSystemAuditRule rule)
    {
        acl.RemoveAuditRuleAll(rule);
        acl.AddAuditRule(rule);
    }

    public (int count, List<string> errors) ApplySacl(string path)
    {
        var errors = new List<string>();
        int count = 0;

        var identity = new NTAccount("Everyone");
        var rights = AuditedRights;

        var folderRule = new FileSystemAuditRule(
            identity, rights,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AuditFlags.Success);

        var fileRule = new FileSystemAuditRule(
            identity, rights,
            InheritanceFlags.None, PropagationFlags.None, AuditFlags.Success);

        // Apply to root folder
        try
        {
            var dirInfo = new DirectoryInfo(path);
            var acl = dirInfo.GetAccessControl(AccessControlSections.Audit);
            ReplaceAuditRule(acl, folderRule);
            dirInfo.SetAccessControl(acl);
            count++;
        }
        catch (Exception ex)
        {
            errors.Add($"(root): {ex.Message}");
        }

        // Apply recursively to existing items
        foreach (var entry in Directory.EnumerateFileSystemEntries(path, "*", SearchOption.AllDirectories))
        {
            try
            {
                if (File.Exists(entry))
                {
                    var fi = new FileInfo(entry);
                    var acl = fi.GetAccessControl(AccessControlSections.Audit);
                    ReplaceAuditRule(acl, fileRule);
                    fi.SetAccessControl(acl);
                }
                else
                {
                    var di = new DirectoryInfo(entry);
                    var acl = di.GetAccessControl(AccessControlSections.Audit);
                    ReplaceAuditRule(acl, folderRule);
                    di.SetAccessControl(acl);
                }
                count++;
            }
            catch (Exception ex)
            {
                errors.Add($"{Path.GetFileName(entry)}: {ex.Message}");
            }
        }

        _logger.LogInformation("SACL applied to {Count} items in {Path}. Errors: {Errors}",
            count, path, errors.Count);
        return (count, errors);
    }

    public (int count, List<string> errors) RemoveSacl(string path)
    {
        var errors = new List<string>();
        int count = 0;

        var identity = new NTAccount("Everyone");
        // RemoveAuditRuleAll removes all audit rules for the given identity regardless of rights/flags
        var removeRule = new FileSystemAuditRule(
            identity, FileSystemRights.ReadData,
            InheritanceFlags.None, PropagationFlags.None, AuditFlags.Success);

        // Remove from root folder
        try
        {
            var dirInfo = new DirectoryInfo(path);
            var acl = dirInfo.GetAccessControl(AccessControlSections.Audit);
            acl.RemoveAuditRuleAll(removeRule);
            dirInfo.SetAccessControl(acl);
            count++;
        }
        catch (Exception ex)
        {
            errors.Add($"(root): {ex.Message}");
        }

        // Remove from all existing items recursively
        foreach (var entry in Directory.EnumerateFileSystemEntries(path, "*", SearchOption.AllDirectories))
        {
            try
            {
                if (File.Exists(entry))
                {
                    var fi = new FileInfo(entry);
                    var acl = fi.GetAccessControl(AccessControlSections.Audit);
                    acl.RemoveAuditRuleAll(removeRule);
                    fi.SetAccessControl(acl);
                }
                else
                {
                    var di = new DirectoryInfo(entry);
                    var acl = di.GetAccessControl(AccessControlSections.Audit);
                    acl.RemoveAuditRuleAll(removeRule);
                    di.SetAccessControl(acl);
                }
                count++;
            }
            catch (Exception ex)
            {
                errors.Add($"{Path.GetFileName(entry)}: {ex.Message}");
            }
        }

        _logger.LogInformation("SACL removed from {Count} items in {Path}. Errors: {Errors}",
            count, path, errors.Count);
        return (count, errors);
    }
}
