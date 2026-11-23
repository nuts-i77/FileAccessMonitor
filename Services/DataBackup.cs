using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace FileAccessMonitor.Services;

// Backup and restore of the data folder (settings, keys, the database), with each file's permissions:
// the keys are readable by SYSTEM, Administrators and the service account only, and must stay so in the
// backup and after a restore.
//
// A backup is a folder <root>/<yyyyMMdd-HHmmss>-<reason> with the files at their relative paths and
// backup.json (written last: a folder without it is incomplete). The database is copied with SQLite's
// backup API, so the service can keep running. Logs, earlier backups and, when the caller cannot read it,
// the collector's folder are left out. chain-head.json (the newest verified chain heads) is copied before
// the database: the heads only move forward, so the copy is never ahead of the copied records.
//
// A restore needs the services stopped. It moves what is in the data folder now to
// backups/<time>-before-restore, puts the backup's files in place with their permissions, and leaves
// restored.json, which the next start writes to the operation log.
public static class DataBackup
{
    public const string FolderName = "backups";
    public const string ManifestFile = "backup.json";
    public const string RestoredMarker = "restored.json";
    public const string DataVersionFile = "version.txt";
    public const string DatabaseFile = "fileaccess.db";

    public const string ReasonManual = "manual";
    public const string ReasonScheduled = "scheduled";
    public const string ReasonPreUpdate = "pre-update";
    public const string ReasonBeforeRestore = "before-restore";

    // How many pre-update backups are kept (the installers make one at each upgrade)
    public const int KeepPreUpdate = 3;

    private static readonly string[] DatabaseFiles =
        [DatabaseFile, DatabaseFile + "-wal", DatabaseFile + "-shm", DatabaseFile + "-journal"];
    private static readonly string[] SkippedFolders = ["logs", FolderName];

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public static string DefaultRoot(string dataDir) => Path.Combine(dataDir, FolderName);

    // Where new backups go: the folder of the daily backup (backup-schedule --to), or the data folder's own
    public static string TargetRoot(string dataDir, string? chosen) => chosen ?? DefaultRoot(dataDir);

    // Where backups are looked for: that folder, and the data folder's own (backups made before a folder was
    // chosen, and those of restores, stay there)
    public static List<string> Roots(string dataDir, string? chosen)
    {
        var roots = new List<string>();
        if (chosen != null) roots.Add(Path.GetFullPath(chosen));
        var own = Path.GetFullPath(DefaultRoot(dataDir));
        if (!roots.Any(r => SamePath(r, own))) roots.Add(own);
        return roots;
    }

    public static List<BackupInfo> ListAll(IEnumerable<string> roots) =>
        roots.SelectMany(List).OrderByDescending(b => b.Created).ToList();

    // A backup by name in any of the roots (or a full path to a backup folder)
    public static BackupInfo? Find(IEnumerable<string> roots, string nameOrPath)
    {
        foreach (var root in roots)
        {
            var folder = Resolve(root, nameOrPath);
            if (folder != null && TryRead(folder) is { } info) return info;
        }
        return null;
    }

    // Why a folder cannot hold backups (a message key), or null. It must be a full path outside the data
    // folder, and the caller must be able to create a folder in it and set its permissions.
    public static string? CheckFolder(string dataDir, string folder)
    {
        if (!Path.IsPathFullyQualified(folder)) return "backup.folderNotAbsolute";
        var full = Path.GetFullPath(folder);
        if (IsUnder(full, dataDir) || IsUnder(dataDir, full)) return "backup.folderInData";
        var probe = Path.Combine(full, $".fam-write-test-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(probe);
            CloseLikeDataDir(dataDir, probe);
            File.WriteAllText(Path.Combine(probe, "test"), "test");
            return null;
        }
        catch (BackupException) { return "backup.cannotProtect"; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return "backup.folderNotWritable";
        }
        finally
        {
            try { if (Directory.Exists(probe)) Directory.Delete(probe, true); } catch { }
        }
    }

    private static bool SamePath(string a, string b) =>
        string.Equals(Path.TrimEndingDirectorySeparator(a), Path.TrimEndingDirectorySeparator(b),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    // ------------------------------------------------------------------ backup

    // Copies the data folder to a new backup folder under root. includeCollector: also the collector's
    // folder (only SYSTEM / root can read it; when it cannot be read it is left out and the result says so).
    public static BackupInfo Create(string dataDir, string root, string reason, string version,
        string? previousVersion = null, bool includeCollector = true, DateTime? now = null)
    {
        dataDir = Path.GetFullPath(dataDir);
        root = Path.GetFullPath(root);
        if (!Directory.Exists(dataDir)) throw new BackupException("backup.noData", dataDir);
        // Inside the data folder only its backups folder: anywhere else the copy would copy itself
        if (IsUnder(root, dataDir) && !IsUnder(root, DefaultRoot(dataDir))) throw new BackupException("backup.badTarget", root);
        var created = now ?? DateTime.UtcNow;
        var name = $"{created.ToLocalTime():yyyyMMdd-HHmmss}-{reason}";
        var folder = Path.Combine(root, name);
        for (var i = 2; Directory.Exists(folder); i++) folder = Path.Combine(root, $"{name}-{i}");
        name = Path.GetFileName(folder);

        EnsureRoot(dataDir, root);
        Directory.CreateDirectory(folder);
        OwnForService(folder);
        if (!IsUnder(root, dataDir))
        {
            try { CloseLikeDataDir(dataDir, folder); }
            catch { try { Directory.Delete(folder, true); } catch { } throw; }
        }
        try
        {
            var entries = new List<BackupEntry>();
            var collectorLeftOut = false;
            var collectorDir = Path.Combine(dataDir, AppPaths.CollectorFolderName);

            // Folders first (their permissions), then files; the database last
            foreach (var dir in Directory.EnumerateDirectories(dataDir, "*", SearchOption.TopDirectoryOnly).Order())
            {
                var rel = Path.GetFileName(dir);
                if (SkippedFolders.Contains(rel, StringComparer.OrdinalIgnoreCase)) continue;
                if (IsUnder(Path.GetFullPath(dir), root)) continue;
                if (string.Equals(rel, AppPaths.CollectorFolderName, StringComparison.OrdinalIgnoreCase)
                    && (!includeCollector || !CanRead(collectorDir)))
                {
                    collectorLeftOut = true;
                    continue;
                }
                CopyTree(dataDir, dir, folder, entries);
            }
            var files = Directory.EnumerateFiles(dataDir, "*", SearchOption.TopDirectoryOnly)
                .Where(f => !DatabaseFiles.Contains(Path.GetFileName(f), StringComparer.OrdinalIgnoreCase)
                            && !Path.GetFileName(f).EndsWith(".tmp", StringComparison.OrdinalIgnoreCase)
                            && !string.Equals(Path.GetFileName(f), RestoredMarker, StringComparison.OrdinalIgnoreCase)
                            && !IsMachineFile(Path.GetFileName(f)))
                // chain-head.json before the database (see above); the rest in name order
                .OrderBy(f => Path.GetFileName(f) == "chain-head.json" ? 0 : 1).ThenBy(f => f, StringComparer.Ordinal);
            foreach (var file in files) entries.Add(CopyFile(dataDir, file, folder));

            var db = Path.Combine(dataDir, DatabaseFile);
            if (File.Exists(db)) entries.Add(SnapshotDatabase(dataDir, db, folder));

            var info = new BackupInfo
            {
                Name = name,
                Created = created,
                Reason = reason,
                AppVersion = version,
                // The installer knows the version installed until now; version.txt is only written by 1.13 and
                // later, so after a reinstall of an earlier version it still names the later one
                DataVersion = previousVersion ?? ReadDataVersion(dataDir),
                PreviousVersion = previousVersion,
                Machine = Environment.MachineName,
                CollectorIncluded = !collectorLeftOut && Directory.Exists(collectorDir),
                Bytes = entries.Where(e => !e.Directory).Sum(e => e.Size),
                RootSddl = OperatingSystem.IsWindows() ? GetSddl(dataDir, true) : null,
                RootMode = OperatingSystem.IsWindows() ? null : (int)File.GetUnixFileMode(dataDir),
                Entries = entries,
            };
            var manifest = Path.Combine(folder, ManifestFile);
            File.WriteAllText(manifest + ".tmp", JsonSerializer.Serialize(info, JsonOptions));
            File.Move(manifest + ".tmp", manifest);
            if (!OperatingSystem.IsWindows() && SecretStore.IsLinuxRoot()) SecretStore.SetLinuxOwner(manifest, root: false);
            info.Path = folder;
            return info;
        }
        catch
        {
            try { Directory.Delete(folder, true); } catch { /* left for the next prune */ }
            throw;
        }
    }

    // The backups under root, newest first (folders without a manifest are incomplete and not listed)
    public static List<BackupInfo> List(string root)
    {
        var list = new List<BackupInfo>();
        if (!Directory.Exists(root)) return list;
        foreach (var dir in Directory.EnumerateDirectories(root))
        {
            var info = TryRead(dir);
            if (info != null) list.Add(info);
        }
        return list.OrderByDescending(b => b.Created).ToList();
    }

    public static BackupInfo? TryRead(string folder)
    {
        try
        {
            var file = Path.Combine(folder, ManifestFile);
            if (!File.Exists(file)) return null;
            var info = JsonSerializer.Deserialize<BackupInfo>(File.ReadAllText(file), JsonOptions);
            if (info == null) return null;
            info.Path = folder;
            info.Name = Path.GetFileName(folder);
            return info;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException) { return null; }
    }

    // Deletes the oldest backups of one reason beyond keep; returns the names deleted
    public static List<string> Prune(string root, string reason, int keep)
    {
        var deleted = new List<string>();
        foreach (var old in List(root).Where(b => b.Reason == reason).Skip(Math.Max(keep, 0)))
        {
            try { Directory.Delete(old.Path!, true); deleted.Add(old.Name); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* next time */ }
        }
        return deleted;
    }

    // A backup folder by its name, inside root only (the name comes from the GUI or the command line)
    public static string? Resolve(string root, string nameOrPath)
    {
        if (string.IsNullOrWhiteSpace(nameOrPath)) return null;
        if (Path.IsPathRooted(nameOrPath)) return Directory.Exists(nameOrPath) ? Path.GetFullPath(nameOrPath) : null;
        if (nameOrPath.IndexOfAny(['/', '\\']) >= 0 || nameOrPath is "." or "..") return null;
        var path = Path.Combine(root, nameOrPath);
        return Directory.Exists(path) ? Path.GetFullPath(path) : null;
    }

    // The files of a backup that are missing or changed (empty: the backup is whole)
    public static List<string> Verify(BackupInfo info)
    {
        var bad = new List<string>();
        foreach (var e in info.Entries.Where(e => !e.Directory))
        {
            var path = Path.Combine(info.Path!, e.Path);
            if (!File.Exists(path)) { bad.Add(e.Path); continue; }
            if (!string.Equals(Hash(path), e.Sha256, StringComparison.OrdinalIgnoreCase)) bad.Add(e.Path);
        }
        return bad;
    }

    // ------------------------------------------------------------------ restore

    // Whether this program may restore the backup: one made by a newer version may need tables or
    // columns this version does not know.
    public static string? RestoreRefusal(BackupInfo info, string currentVersion)
    {
        var data = ParseVersion(info.DataVersion ?? info.AppVersion);
        var current = ParseVersion(currentVersion);
        if (data == null || current == null || current == new Version(0, 0, 0)) return null;
        return data > current ? "backup.newer" : null;
    }

    // Puts the backup in place of the data folder's content. The services must be stopped. Returns the
    // folder that now holds what was there before.
    public static string Restore(string dataDir, BackupInfo info, DateTime? now = null)
    {
        dataDir = Path.GetFullPath(dataDir);
        var root = DefaultRoot(dataDir);
        var bad = Verify(info);
        if (bad.Count > 0) throw new BackupException("backup.damaged", string.Join(", ", bad.Take(5)));
        var db = Path.Combine(dataDir, DatabaseFile);
        if (File.Exists(db) && !CanOpenExclusively(db)) throw new BackupException("backup.inUse", db);

        // What is there now goes into a backup folder of its own (moved: same volume, fast)
        var stamp = (now ?? DateTime.UtcNow).ToLocalTime().ToString("yyyyMMdd-HHmmss");
        var safety = Path.Combine(root, $"{stamp}-{ReasonBeforeRestore}");
        for (var i = 2; Directory.Exists(safety); i++) safety = Path.Combine(root, $"{stamp}-{ReasonBeforeRestore}-{i}");
        EnsureRoot(dataDir, root);
        Directory.CreateDirectory(safety);
        OwnForService(safety);
        var restoringFromInside = IsUnder(Path.GetFullPath(info.Path!), root);
        foreach (var entry in Directory.EnumerateFileSystemEntries(dataDir).ToList())
        {
            var name = Path.GetFileName(entry);
            if (SkippedFolders.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;
            // A backup without the collector's folder (made from the GUI) leaves the current one in place:
            // its secret and unsent records still belong to this machine
            if (!info.CollectorIncluded && string.Equals(name, AppPaths.CollectorFolderName, StringComparison.OrdinalIgnoreCase)) continue;
            if (IsMachineFile(name)) continue;
            if (!restoringFromInside && IsUnder(Path.GetFullPath(info.Path!), Path.GetFullPath(entry))) continue;
            var target = Path.Combine(safety, name);
            if (Directory.Exists(entry)) Directory.Move(entry, target); else File.Move(entry, target);
        }
        // Its manifest lists the moved files as they are, so this folder can be restored like any backup
        var moved = Describe(safety);
        File.WriteAllText(Path.Combine(safety, ManifestFile), JsonSerializer.Serialize(new BackupInfo
        {
            Name = Path.GetFileName(safety), Created = now ?? DateTime.UtcNow, Reason = ReasonBeforeRestore,
            AppVersion = AppInfo.Version, DataVersion = ReadDataVersion(safety), Machine = Environment.MachineName,
            CollectorIncluded = Directory.Exists(Path.Combine(safety, AppPaths.CollectorFolderName)),
            Bytes = moved.Where(e => !e.Directory).Sum(e => e.Size),
            RootSddl = info.RootSddl, RootMode = info.RootMode, Entries = moved,
        }, JsonOptions));
        if (!OperatingSystem.IsWindows() && SecretStore.IsLinuxRoot())
            SecretStore.SetLinuxOwner(Path.Combine(safety, ManifestFile), root: false);

        // The backup's folders, then files, with their permissions
        foreach (var e in info.Entries.Where(e => e.Directory))
        {
            var target = Path.Combine(dataDir, e.Path);
            Directory.CreateDirectory(target);
            ApplyPermissions(target, true, e);
        }
        foreach (var e in info.Entries.Where(e => !e.Directory && !IsMachineFile(e.Path)))
        {
            var target = Path.Combine(dataDir, e.Path);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(Path.Combine(info.Path!, e.Path), target, overwrite: true);
            ApplyPermissions(target, false, e);
        }
        if (OperatingSystem.IsWindows() && info.RootSddl != null) SetSddl(dataDir, true, info.RootSddl);

        File.WriteAllText(Path.Combine(dataDir, RestoredMarker), JsonSerializer.Serialize(new RestoredMarkerInfo(
            info.Name, info.Created, info.AppVersion, info.DataVersion, now ?? DateTime.UtcNow, Path.GetFileName(safety)), JsonOptions));
        if (OperatingSystem.IsLinux()) SecretStore.SetLinuxOwner(Path.Combine(dataDir, RestoredMarker), root: false);
        return safety;
    }

    // Read (and removed) by the first start after a restore, for the operation log
    public static RestoredMarkerInfo? TakeRestoredMarker(string dataDir)
    {
        var file = Path.Combine(dataDir, RestoredMarker);
        try
        {
            if (!File.Exists(file)) return null;
            var marker = JsonSerializer.Deserialize<RestoredMarkerInfo>(File.ReadAllText(file), JsonOptions);
            File.Delete(file);
            return marker;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException) { return null; }
    }

    // ------------------------------------------------------------------ the version the data was last used with

    public static void WriteDataVersion(string dataDir, string version)
    {
        try
        {
            var file = Path.Combine(dataDir, DataVersionFile);
            if (File.Exists(file) && File.ReadAllText(file).Trim() == version) return;
            File.WriteAllText(file, version + Environment.NewLine);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* only for backups */ }
    }

    public static string? ReadDataVersion(string dataDir)
    {
        try
        {
            var file = Path.Combine(dataDir, DataVersionFile);
            return File.Exists(file) ? File.ReadAllText(file).Trim() is { Length: > 0 } v ? v : null : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    // "1.13.0-rc1" -> 1.13.0; null when it is not a version
    public static Version? ParseVersion(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var core = text.Trim().Split('-', '+')[0];
        return Version.TryParse(core, out var v) ? new Version(v.Major, v.Minor, Math.Max(v.Build, 0)) : null;
    }

    // ------------------------------------------------------------------ copying

    private static void CopyTree(string dataDir, string dir, string folder, List<BackupEntry> entries)
    {
        entries.Add(DirEntry(dataDir, dir, folder));
        foreach (var sub in Directory.EnumerateDirectories(dir).Order(StringComparer.Ordinal))
            CopyTree(dataDir, sub, folder, entries);
        foreach (var file in Directory.EnumerateFiles(dir).Order(StringComparer.Ordinal))
            entries.Add(CopyFile(dataDir, file, folder));
    }

    private static BackupEntry DirEntry(string dataDir, string dir, string folder)
    {
        var rel = Path.GetRelativePath(dataDir, dir);
        var target = Path.Combine(folder, rel);
        Directory.CreateDirectory(target);
        var entry = new BackupEntry { Path = rel.Replace('\\', '/'), Directory = true };
        CapturePermissions(dir, true, entry);
        ApplyPermissions(target, true, entry);
        return entry;
    }

    private static BackupEntry CopyFile(string dataDir, string file, string folder)
    {
        var rel = Path.GetRelativePath(dataDir, file);
        var target = Path.Combine(folder, rel);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        using (var src = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        using (var dst = new FileStream(target, FileMode.CreateNew, FileAccess.Write))
            src.CopyTo(dst);
        var entry = new BackupEntry { Path = rel.Replace('\\', '/'), Size = new FileInfo(target).Length, Sha256 = Hash(target) };
        CapturePermissions(file, false, entry);
        ApplyPermissions(target, false, entry);
        return entry;
    }

    // A consistent copy of the database while the service may be writing to it
    private static BackupEntry SnapshotDatabase(string dataDir, string db, string folder)
    {
        var target = Path.Combine(folder, DatabaseFile);
        using (var src = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = db, Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString()))
        using (var dst = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = target, Pooling = false }.ToString()))
        {
            src.Open();
            dst.Open();
            src.BackupDatabase(dst);
            // One file: the copy needs no -wal next to it
            using var cmd = dst.CreateCommand();
            cmd.CommandText = "PRAGMA journal_mode=DELETE";
            cmd.ExecuteNonQuery();
        }
        var entry = new BackupEntry { Path = DatabaseFile, Size = new FileInfo(target).Length, Sha256 = Hash(target) };
        CapturePermissions(db, false, entry);
        ApplyPermissions(target, false, entry);
        return entry;
    }

    // The backups folder: inside the data folder it inherits its permissions; elsewhere it gets them
    private static void EnsureRoot(string dataDir, string root)
    {
        var existed = Directory.Exists(root);
        Directory.CreateDirectory(root);
        if (IsUnder(root, dataDir))
        {
            // Linux, as root (the package before an upgrade): the service account makes backups here too
            if (!OperatingSystem.IsWindows()) OwnForService(root);
            return;
        }
        if (!existed) CloseLikeDataDir(dataDir, root);
    }

    // A folder outside the data folder gets the data folder's access rules, not those of where it is put
    // (D:\Backups or a share may be readable by Users). Each backup folder gets them too, so a backup stays
    // closed in a chosen folder that is open. Throws when the rules cannot be set (a share without ACLs):
    // the keys must not land where anyone can read them.
    private static void CloseLikeDataDir(string dataDir, string folder)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                var security = new DirectorySecurity();
                security.SetSecurityDescriptorSddlForm(GetSddl(dataDir, true), AccessControlSections.Access);
                var rules = security.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                var own = new DirectorySecurity();
                own.SetAccessRuleProtection(true, false);
                foreach (FileSystemAccessRule r in rules)
                    own.AddAccessRule(new FileSystemAccessRule(r.IdentityReference, r.FileSystemRights, r.InheritanceFlags, r.PropagationFlags, r.AccessControlType));
                new DirectoryInfo(folder).SetAccessControl(own);
            }
            else
            {
                OwnForService(folder);
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PlatformNotSupportedException
                                       or InvalidOperationException or System.Security.Principal.IdentityNotMappedException)
        {
            throw new BackupException("backup.cannotProtect", $"{folder} ({ex.Message})");
        }
    }

    // Linux: owner only, and the service account when run as root
    private static void OwnForService(string path)
    {
        if (OperatingSystem.IsWindows()) return;
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        if (SecretStore.IsLinuxRoot()) SecretStore.SetLinuxOwner(path, root: false);
    }

    private static void CapturePermissions(string path, bool dir, BackupEntry entry)
    {
        if (OperatingSystem.IsWindows()) entry.Sddl = GetSddl(path, dir);
        else
        {
            entry.Mode = (int)File.GetUnixFileMode(path);
            entry.RootOwned = IsCollectorPath(entry.Path);
        }
    }

    private static void ApplyPermissions(string path, bool dir, BackupEntry entry)
    {
        if (OperatingSystem.IsWindows())
        {
            if (entry.Sddl != null) SetSddl(path, dir, entry.Sddl);
            return;
        }
        if (entry.Mode is { } mode) File.SetUnixFileMode(path, (UnixFileMode)mode);
        if (SecretStore.IsLinuxRoot()) SecretStore.SetLinuxOwner(path, entry.RootOwned);
    }

    // Files about this machine, not the data: what backup-schedule set up describes the task or timer here, so
    // it is neither backed up nor replaced by a restore
    private static bool IsMachineFile(string rel) =>
        string.Equals(rel, BackupSchedule.InfoFile, StringComparison.OrdinalIgnoreCase);

    private static bool IsCollectorPath(string rel) =>
        rel.Equals(AppPaths.CollectorFolderName, StringComparison.Ordinal)
        || rel.StartsWith(AppPaths.CollectorFolderName + "/", StringComparison.Ordinal);

    [SupportedOSPlatform("windows")]
    private static string GetSddl(string path, bool dir)
    {
        FileSystemSecurity security = dir
            ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access)
            : new FileInfo(path).GetAccessControl(AccessControlSections.Access);
        return security.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
    }

    // Explicit rules and the protection flag are set; rules marked as inherited are taken from the new parent
    [SupportedOSPlatform("windows")]
    private static void SetSddl(string path, bool dir, string sddl)
    {
        if (dir)
        {
            var s = new DirectorySecurity();
            s.SetSecurityDescriptorSddlForm(sddl, AccessControlSections.Access);
            new DirectoryInfo(path).SetAccessControl(s);
        }
        else
        {
            var s = new FileSecurity();
            s.SetSecurityDescriptorSddlForm(sddl, AccessControlSections.Access);
            new FileInfo(path).SetAccessControl(s);
        }
    }

    private static bool CanRead(string dir)
    {
        try { _ = Directory.EnumerateFileSystemEntries(dir).FirstOrDefault(); return true; }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { return false; }
    }

    private static bool CanOpenExclusively(string file)
    {
        try { using var _ = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None); return true; }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    private static bool IsUnder(string path, string parent)
    {
        var p = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var q = Path.TrimEndingDirectorySeparator(Path.GetFullPath(parent));
        var cmp = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return p.Equals(q, cmp) || p.StartsWith(q + Path.DirectorySeparatorChar, cmp);
    }

    // The entries of a folder as it is (the files moved away by a restore, database files included)
    private static List<BackupEntry> Describe(string folder)
    {
        var entries = new List<BackupEntry>();
        void Walk(string dir)
        {
            foreach (var sub in Directory.EnumerateDirectories(dir).Order(StringComparer.Ordinal))
            {
                var e = new BackupEntry { Path = Path.GetRelativePath(folder, sub).Replace('\\', '/'), Directory = true };
                CapturePermissions(sub, true, e);
                entries.Add(e);
                Walk(sub);
            }
            foreach (var file in Directory.EnumerateFiles(dir).Order(StringComparer.Ordinal))
            {
                var rel = Path.GetRelativePath(folder, file).Replace('\\', '/');
                if (rel == ManifestFile) continue;
                var e = new BackupEntry { Path = rel, Size = new FileInfo(file).Length, Sha256 = Hash(file) };
                CapturePermissions(file, false, e);
                entries.Add(e);
            }
        }
        Walk(folder);
        return entries;
    }

    private static string Hash(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }
}

public class BackupInfo
{
    public string Name { get; set; } = "";
    public DateTime Created { get; set; }
    public string Reason { get; set; } = "";
    // The version that made the backup, and the one the data was last used with (version.txt; for an
    // upgrade from before 1.13 the version the installer passes)
    public string AppVersion { get; set; } = "";
    public string? DataVersion { get; set; }
    public string? PreviousVersion { get; set; }
    public string Machine { get; set; } = "";
    public bool CollectorIncluded { get; set; }
    public long Bytes { get; set; }
    public string? RootSddl { get; set; }
    public int? RootMode { get; set; }
    public List<BackupEntry> Entries { get; set; } = [];
    [System.Text.Json.Serialization.JsonIgnore] public string? Path { get; set; }
}

public class BackupEntry
{
    public string Path { get; set; } = "";
    public bool Directory { get; set; }
    public long Size { get; set; }
    public string? Sha256 { get; set; }
    // Windows: the access rules (DACL) as SDDL; Linux: the mode, and whether root owns it (the collector's folder)
    public string? Sddl { get; set; }
    public int? Mode { get; set; }
    public bool RootOwned { get; set; }
}

public record RestoredMarkerInfo(string Backup, DateTime BackupCreated, string AppVersion, string? DataVersion,
    DateTime RestoredAt, string PreviousDataSavedAs);

// A message key of Messages and its argument
public class BackupException(string key, string? arg = null) : Exception(arg == null ? key : $"{key}: {arg}")
{
    public string Key { get; } = key;
    public string? Arg { get; } = arg;
}
