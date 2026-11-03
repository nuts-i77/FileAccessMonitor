using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;

namespace FileAccessMonitor.Services;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class SaclManagerService
{
    private readonly ILogger<SaclManagerService> _logger;

    public SaclManagerService(ILogger<SaclManagerService> logger)
    {
        _logger = logger;
    }

    // File System: the SACL entries (success and failure) only produce events when this is on.
    // Authorization Policy Change: event 4670 (permissions changed) is documented under this
    // subcategory, although File System auditing is said to log it for files too. Both are enabled
    // until a test on a real machine shows which one is needed (VERIFY).
    private static readonly string[] AuditSubcategories =
    [
        "{0CCE921D-69AE-11D9-BED3-505054503030}",
        "{0CCE9231-69AE-11D9-BED3-505054503030}",
    ];

    public void EnableAuditPolicy()
    {
        foreach (var subcategory in AuditSubcategories)
        {
            try
            {
                var psi = new ProcessStartInfo("auditpol.exe",
                    $"/set /subcategory:\"{subcategory}\" /success:enable /failure:enable")
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                proc?.WaitForExit(5000);
                _logger.LogInformation("Audit policy {Subcategory} enabled.", subcategory);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to enable audit policy {Subcategory}.", subcategory);
            }
        }
    }

    // "File System" audit subcategory, as set by EnableAuditPolicy
    private static readonly Guid FileSystemSubcategory = new("0CCE921D-69AE-11D9-BED3-505054503030");
    private const uint PolicyAuditEventSuccess = 1;
    private const uint PolicyAuditEventFailure = 2;

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AuditQuerySystemPolicy(Guid[] subCategoryGuids, uint policyCount, out IntPtr auditPolicy);

    [System.Runtime.InteropServices.DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);

    // Whether successful file access is audited (without it nothing is recorded); null if unknown.
    // Read through the API rather than auditpol's output, which is localized.
    public static bool? IsFileSystemAuditOn() => QueryFileSystemAudit(PolicyAuditEventSuccess);

    // Whether refused file access is audited too (needed for Denied records); null if unknown.
    public static bool? IsFileSystemFailureAuditOn() => QueryFileSystemAudit(PolicyAuditEventFailure);

    private static bool? QueryFileSystemAudit(uint flag)
    {
        try
        {
            if (!AuditQuerySystemPolicy([FileSystemSubcategory], 1, out var buffer)) return null;
            try
            {
                var info = System.Runtime.InteropServices.Marshal.PtrToStructure<AuditPolicyInformation>(buffer);
                return (info.AuditingInformation & flag) != 0;
            }
            finally
            {
                AuditFree(buffer);
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return null;
        }
    }

    // Only rights that the collector turns into Read/Write/Delete/Permission records.
    // FileSystemRights.Read/Write would also audit ReadAttributes, ReadEA,
    // ReadPermissions, WriteAttributes etc., which floods the Security log
    // (e.g. media indexers scanning metadata) without producing any records.
    // ChangePermissions and TakeOwnership are rare. Their 4663 events are ignored by the
    // collector; the 4670 event that follows a change carries the before/after.
    internal const FileSystemRights AuditedRights =
        FileSystemRights.ReadData | FileSystemRights.WriteData |
        FileSystemRights.AppendData | FileSystemRights.Delete |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    // One entry for both outcomes: success gives the access events, failure the refused attempts.
    internal const AuditFlags AuditedFlags = AuditFlags.Success | AuditFlags.Failure;

    // Folders this service cannot open (a deny entry, for example) are skipped instead of ending the
    // whole walk; they keep their old SACL
    private static readonly EnumerationOptions WalkOptions = new()
    {
        RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = 0,
    };

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
            PropagationFlags.None, AuditedFlags);

        var fileRule = new FileSystemAuditRule(
            identity, rights,
            InheritanceFlags.None, PropagationFlags.None, AuditedFlags);

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
        foreach (var entry in Directory.EnumerateFileSystemEntries(path, "*", WalkOptions))
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
        foreach (var entry in Directory.EnumerateFileSystemEntries(path, "*", WalkOptions))
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
