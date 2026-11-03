using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json.Nodes;

namespace FileAccessMonitor.Services;

// Reads the DACLs below a folder on Windows (agent and standalone server). Folders and files are
// listed when they carry explicit entries or do not inherit; the root lists every entry.
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public static class PermissionScanWindows
{
    // Name lookups can hang when a domain controller is unreachable; after this much time in
    // total the remaining SIDs stay as text
    private static readonly TimeSpan LookupBudget = TimeSpan.FromSeconds(5);

    public static JsonObject Scan(string root, PermissionScanOptions requested, CancellationToken ct)
    {
        var o = PermissionContract.Clamp(requested);
        var result = new PermissionResultBuilder("windows", root, o);
        var clock = Stopwatch.StartNew();
        var names = new SidNames();
        var limit = TimeSpan.FromSeconds(o.TimeLimitSeconds);

        var queue = new Queue<(string Path, int Depth, string Rel, SecurityIdentifier? ParentOwner)>();
        queue.Enqueue((root, 0, "", null));
        var listing = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = 0 };

        while (queue.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            if (result.Truncated) break;
            if (clock.Elapsed > limit) { result.Truncate("time"); break; }
            if (result.Folders >= o.MaxFolders) { result.Truncate("folders"); break; }
            var (path, depth, rel, parentOwner) = queue.Dequeue();
            result.CountFolder();

            var isRoot = depth == 0;
            var owner = ReadObject(path, true, isRoot, parentOwner, rel, names, result, out var folderRow);
            if (folderRow != null && (isRoot || folderRow.Flags != PermissionContract.FlagFolder))
                result.AddRow(rel, folderRow.Flags, folderRow.OwnerIdx, folderRow.Aces);

            DirectoryInfo dir;
            try { dir = new DirectoryInfo(path); }
            catch (Exception) { continue; }

            if (o.IncludeFiles && !ScanFiles(dir, rel, owner, o, names, result, listing, clock, limit, ct)) break;

            if (depth >= o.MaxDepth)
            {
                try { if (dir.EnumerateDirectories("*", listing).Any(d => !IsReparsePoint(d))) result.Truncate("depth"); }
                catch (Exception) { /* nothing to descend into anyway */ }
                continue;
            }
            try
            {
                foreach (var sub in dir.EnumerateDirectories("*", listing).OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase))
                {
                    // Junctions and symbolic links are not followed: no loops, no leaving the share
                    if (IsReparsePoint(sub)) continue;
                    queue.Enqueue((sub.FullName, depth + 1, rel.Length == 0 ? sub.Name : rel + "\\" + sub.Name, owner));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                result.AddError($"{path}: {ex.Message}");
            }
        }
        return result.Build();
    }

    private static bool ScanFiles(DirectoryInfo dir, string rel, SecurityIdentifier? dirOwner, PermissionScanOptions o,
        SidNames names, PermissionResultBuilder result, EnumerationOptions listing, Stopwatch clock, TimeSpan limit,
        CancellationToken ct)
    {
        try
        {
            foreach (var file in dir.EnumerateFiles("*", listing))
            {
                ct.ThrowIfCancellationRequested();
                if (IsReparsePoint(file)) continue;
                if (result.Files >= o.MaxFiles) { result.Truncate("files"); return false; }
                if (result.Truncated) return false;
                if (clock.Elapsed > limit) { result.Truncate("time"); return false; }
                result.CountFile();
                var fileRel = rel.Length == 0 ? file.Name : rel + "\\" + file.Name;
                ReadObject(file.FullName, false, false, dirOwner, fileRel, names, result, out var row);
                if (row != null && row.Flags != 0) result.AddRow(fileRel, row.Flags, row.OwnerIdx, row.Aces);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            result.AddError($"{dir.FullName}: {ex.Message}");
        }
        return true;
    }

    private static bool IsReparsePoint(FileSystemInfo info) => (info.Attributes & FileAttributes.ReparsePoint) != 0;

    internal sealed record RowData(int Flags, int OwnerIdx, List<PermissionAce> Aces);

    // The row of one folder or file: null when it cannot even be tried (does not happen now). Flags
    // is only the folder bit when nothing is worth listing.
    private static SecurityIdentifier? ReadObject(string path, bool folder, bool isRoot, SecurityIdentifier? parentOwner,
        string rel, SidNames names, PermissionResultBuilder result, out RowData? row)
    {
        var baseFlags = folder ? PermissionContract.FlagFolder : 0;
        FileSystemSecurity security;
        try
        {
            security = folder
                ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner)
                : new FileInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException or PrivilegeNotHeldException)
        {
            result.AddError($"{path}: not readable");
            row = new RowData(baseFlags | PermissionContract.FlagNotReadable, -1, []);
            return null;
        }

        SecurityIdentifier? owner = null;
        try { owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier; }
        catch (Exception ex) when (ex is IdentityNotMappedException or InvalidOperationException or UnauthorizedAccessException) { }

        var flags = baseFlags;
        if (security.AreAccessRulesProtected) flags |= PermissionContract.FlagInheritanceBroken;
        var aces = new List<PermissionAce>();
        var explicitSeen = false;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (!rule.IsInherited) explicitSeen = true;
            // Below the root the inherited entries equal the parent's, so only the explicit ones are sent
            if (rule.IsInherited && !isRoot) continue;
            var level = MapRights(rule.FileSystemRights);
            if (level == 0) continue;
            var sid = (SecurityIdentifier)rule.IdentityReference;
            aces.Add(new PermissionAce(result.Principal(names.Name(sid), sid.Value),
                rule.AccessControlType == AccessControlType.Deny ? 1 : 0, level, ScopeOf(rule, folder)));
        }
        if (explicitSeen) flags |= PermissionContract.FlagExplicit;

        var ownerIdx = -1;
        if (owner != null && (isRoot || (parentOwner != null && !owner.Equals(parentOwner))))
        {
            ownerIdx = result.Principal(names.Name(owner), owner.Value);
            if (!isRoot) flags |= PermissionContract.FlagOwnerDiffers;
        }

        // Worth a row: explicit entries, an interrupted inheritance, or the root
        var worth = isRoot || (flags & (PermissionContract.FlagExplicit | PermissionContract.FlagInheritanceBroken)) != 0;
        row = worth ? new RowData(flags, ownerIdx, aces) : new RowData(baseFlags, -1, []);
        return owner ?? parentOwner;
    }

    // Level bits of a rights mask (the same for allow and deny entries)
    public static int MapRights(FileSystemRights rights)
    {
        var level = 0;
        if ((rights & FileSystemRights.ReadData) != 0) level |= PermissionContract.Read;
        if ((rights & (FileSystemRights.WriteData | FileSystemRights.AppendData)) != 0) level |= PermissionContract.Write;
        if ((rights & (FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles)) != 0) level |= PermissionContract.Delete;
        if ((rights & (FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership)) != 0) level |= PermissionContract.Perm;
        if ((rights & FileSystemRights.ExecuteFile) != 0) level |= PermissionContract.Exec;
        return level;
    }

    // Where an entry applies. Files only have "this object".
    internal static int ScopeOf(FileSystemAccessRule rule, bool folder)
    {
        if (!folder) return PermissionContract.ScopeThis;
        var scope = 0;
        if ((rule.PropagationFlags & PropagationFlags.InheritOnly) == 0) scope |= PermissionContract.ScopeThis;
        if ((rule.InheritanceFlags & InheritanceFlags.ContainerInherit) != 0) scope |= PermissionContract.ScopeSubfolders;
        if ((rule.InheritanceFlags & InheritanceFlags.ObjectInherit) != 0) scope |= PermissionContract.ScopeFiles;
        return scope;
    }

    // SID -> name, once per SID; a SID that cannot be resolved (AppContainer, deleted account) stays text
    private sealed class SidNames
    {
        private readonly Dictionary<string, string> _cache = [];
        private readonly Stopwatch _spent = new();

        public string Name(SecurityIdentifier sid)
        {
            if (_cache.TryGetValue(sid.Value, out var cached)) return cached;
            var name = sid.Value;
            if (_spent.Elapsed < LookupBudget)
            {
                _spent.Start();
                try { name = ((NTAccount)sid.Translate(typeof(NTAccount))).Value; }
                catch (Exception ex) when (ex is IdentityNotMappedException or SystemException) { }
                finally { _spent.Stop(); }
            }
            return _cache[sid.Value] = name;
        }
    }
}
