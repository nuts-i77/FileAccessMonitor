using System.Diagnostics;
using System.Runtime.Versioning;

namespace FileAccessMonitor.Services;

// The command line of backups (also run by the installers before an upgrade):
//   backup  [--to <folder>] [--keep <n>] [--reason <word>] [--previous <version>]
//   backups [--to <folder>] [--delete <name>]
//   restore <name or folder> [--force] [--no-service]
//   backup-schedule ...  (the daily backup, see BackupSchedule)
// Run elevated (Windows) or as root (Linux): the keys in the data folder are readable by the services and
// administrators only. restore stops the services, puts the backup in place and starts again those that ran.
public static class BackupCommand
{
    private const string Usage =
        "Usage:\n" +
        "  FileAccessMonitor backup [--to <folder>] [--keep <n>] [--reason <word>] [--previous <version>]\n" +
        "  FileAccessMonitor backups [--to <folder>] [--delete <name>]\n" +
        "  FileAccessMonitor restore <name or folder> [--force] [--no-service]\n" +
        "  FileAccessMonitor backup-schedule [--time HH:MM] [--keep <n>] [--to <folder>] | --off\n" +
        "Backups go to the folder of the daily backup (or <data folder>/backups) unless --to is given;\n" +
        "--keep deletes the oldest backups of the same kind beyond that number.";

    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        var verb = args[0];
        string? to = null, reason = null, previous = null, target = null, delete = null;
        int? keep = null;
        var force = false;
        var noService = false;
        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--to" when i + 1 < args.Length: to = args[++i]; break;
                case "--reason" when i + 1 < args.Length: reason = args[++i]; break;
                case "--previous" when i + 1 < args.Length: previous = args[++i]; break;
                case "--keep" when verb == "backup" && i + 1 < args.Length && int.TryParse(args[i + 1], out var k) && k is >= 1 and <= 365:
                    keep = k; i++; break;
                case "--delete" when verb == "backups" && i + 1 < args.Length: delete = args[++i]; break;
                case "--force": force = true; break;
                case "--no-service": noService = true; break;
                case "-h" or "--help": output.WriteLine(Usage); return 0;
                default:
                    if (verb == "restore" && target == null && !args[i].StartsWith("--")) { target = args[i]; break; }
                    error.WriteLine($"Unknown argument: {args[i]}");
                    error.WriteLine(Usage);
                    return 2;
            }
        }
        if (reason != null && !System.Text.RegularExpressions.Regex.IsMatch(reason, "^[a-z0-9-]{1,32}$"))
        {
            error.WriteLine("--reason takes lower-case letters, digits and hyphens.");
            return 2;
        }

        var dataDir = AppPaths.BaseDataDir;
        // The folder of the daily backup, unless --to is given; backups are looked for there and in the data
        // folder's own backups folder
        var chosen = BackupSchedule.Read(dataDir)?.To;
        var root = to != null ? Path.GetFullPath(to) : DataBackup.TargetRoot(dataDir, chosen);
        var roots = to != null ? [root] : DataBackup.Roots(dataDir, chosen);
        // A FILEACCESSMONITOR_DATA folder (development, a second instance) belongs to whoever runs it
        var ownData = Environment.GetEnvironmentVariable("FILEACCESSMONITOR_DATA") is { Length: > 0 };
        if (!ownData && !IsElevated())
        {
            error.WriteLine(OperatingSystem.IsWindows()
                ? "Run this from an elevated (Administrator) prompt: the data folder holds keys only the services and administrators can read."
                : "Run this as root (sudo): the data folder holds keys only the services and root can read.");
            return 1;
        }

        if (verb == "backup-schedule")
        {
            // The task or timer backs up the installed data folder, not a FILEACCESSMONITOR_DATA one
            if (ownData) { error.WriteLine("backup-schedule sets up the installed data folder; unset FILEACCESSMONITOR_DATA."); return 2; }
            return BackupSchedule.Run(args, dataDir, Environment.ProcessPath ?? "FileAccessMonitor", output, error);
        }

        try
        {
            switch (verb)
            {
                case "backup":
                {
                    var why = reason ?? DataBackup.ReasonManual;
                    BackupInfo info;
                    try { info = DataBackup.Create(dataDir, root, why, AppInfo.Version, previous); }
                    catch (Exception ex) when (why == DataBackup.ReasonPreUpdate && to == null && chosen != null
                                               && ex is IOException or UnauthorizedAccessException or BackupException)
                    {
                        // Before an upgrade a backup matters more than where it is: the chosen folder (a share the
                        // installing account cannot reach, ...) failed, so the data folder's own is used
                        error.WriteLine($"The backup folder {root} could not be used ({ex.Message}); backing up to the data folder instead.");
                        root = DataBackup.DefaultRoot(dataDir);
                        info = DataBackup.Create(dataDir, root, why, AppInfo.Version, previous);
                    }
                    if (keep != null || why == DataBackup.ReasonPreUpdate)
                        DataBackup.Prune(root, why, keep ?? DataBackup.KeepPreUpdate);
                    output.WriteLine($"Backup written: {info.Path}");
                    output.WriteLine($"  {Size(info.Bytes)}, data of version {info.DataVersion ?? "unknown"}" +
                                     (info.CollectorIncluded ? ", with the collector's folder" : ""));
                    return 0;
                }
                case "backups" when delete != null:
                {
                    var folder = DataBackup.Find(roots, delete)?.Path;
                    if (folder == null)
                    {
                        error.WriteLine(Messages.Get("backup.notFound", delete));
                        return 1;
                    }
                    Directory.Delete(folder, true);
                    output.WriteLine(Messages.Get("backup.deleted", delete));
                    return 0;
                }
                case "backups":
                {
                    var list = DataBackup.ListAll(roots);
                    if (list.Count == 0) { output.WriteLine($"No backups in {string.Join(" or ", roots)}."); return 0; }
                    output.WriteLine("Backups (newest first):");
                    foreach (var b in list)
                        output.WriteLine($"  {b.Name,-36} {b.Created.ToLocalTime():yyyy-MM-dd HH:mm}  {b.Reason,-14} v{b.DataVersion ?? b.AppVersion,-12} {Size(b.Bytes),9}  {Path.GetDirectoryName(b.Path)}");
                    output.WriteLine("Restore one with: FileAccessMonitor restore <name>");
                    return 0;
                }
                case "restore":
                    if (target == null) { error.WriteLine(Usage); return 2; }
                    return Restore(dataDir, roots, target, force, noService, output, error);
            }
        }
        catch (BackupException ex)
        {
            error.WriteLine(Messages.Get(ex.Key, ex.Arg ?? ""));
            return 1;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Microsoft.Data.Sqlite.SqliteException)
        {
            error.WriteLine($"Failed: {ex.Message}");
            return 1;
        }
        error.WriteLine(Usage);
        return 2;
    }

    private static int Restore(string dataDir, List<string> roots, string target, bool force, bool noService, TextWriter output, TextWriter error)
    {
        var info = DataBackup.Find(roots, target);
        if (info == null)
        {
            error.WriteLine($"No backup \"{target}\" in {string.Join(" or ", roots)} (list them with: FileAccessMonitor backups).");
            return 1;
        }
        if (DataBackup.RestoreRefusal(info, AppInfo.Version) is { } refusal && !force)
        {
            error.WriteLine(Messages.Get(refusal, info.DataVersion ?? info.AppVersion, AppInfo.Version));
            return 1;
        }

        // The installed services use the installed data folder; a FILEACCESSMONITOR_DATA folder is not theirs
        var services = noService || Environment.GetEnvironmentVariable("FILEACCESSMONITOR_DATA") is { Length: > 0 }
            ? [] : ServiceNames();
        var running = services.Where(IsRunning).ToList();
        foreach (var s in running)
        {
            output.WriteLine($"Stopping {s} ...");
            if (!Stop(s)) { error.WriteLine($"{s} did not stop; nothing was changed."); return 1; }
        }
        string saved;
        try
        {
            saved = DataBackup.Restore(dataDir, info);
        }
        finally
        {
            foreach (var s in running)
            {
                output.WriteLine($"Starting {s} ...");
                if (!Start(s)) error.WriteLine($"{s} did not start; start it yourself.");
            }
        }
        output.WriteLine($"Restored {info.Name} (made {info.Created.ToLocalTime():yyyy-MM-dd HH:mm}, data of version {info.DataVersion ?? info.AppVersion}).");
        output.WriteLine($"What was there before is kept in {saved}; restore that to undo.");
        if (!info.CollectorIncluded && Directory.Exists(Path.Combine(dataDir, AppPaths.CollectorFolderName)))
            output.WriteLine("The backup has no collector folder (backups made from the web GUI leave it out): the current one was kept.");
        output.WriteLine("Records received after the backup was made are not in the restored database.");
        return 0;
    }

    // The services of this install: the agent has only the one
    private static string[] ServiceNames() => OperatingSystem.IsWindows()
        ? ["FileAccessMonitorCollector", "FileAccessMonitor"]
        : ["fileaccessmonitor-collector", "fileaccessmonitor"];

    private static bool IsRunning(string name)
    {
        if (OperatingSystem.IsWindows()) return WindowsServiceRunning(name);
        return RunTool("systemctl", $"is-active --quiet {name}") == 0;
    }

    private static bool Stop(string name)
    {
        if (OperatingSystem.IsWindows()) return WindowsServiceSet(name, start: false);
        return RunTool("systemctl", $"stop {name}") == 0;
    }

    private static bool Start(string name)
    {
        if (OperatingSystem.IsWindows()) return WindowsServiceSet(name, start: true);
        return RunTool("systemctl", $"start {name}") == 0;
    }

    [SupportedOSPlatform("windows")]
    private static bool WindowsServiceRunning(string name)
    {
        try
        {
            using var sc = new System.ServiceProcess.ServiceController(name);
            return sc.Status is not (System.ServiceProcess.ServiceControllerStatus.Stopped
                or System.ServiceProcess.ServiceControllerStatus.StopPending);
        }
        catch (InvalidOperationException) { return false; }   // not installed
    }

    [SupportedOSPlatform("windows")]
    private static bool WindowsServiceSet(string name, bool start)
    {
        try
        {
            using var sc = new System.ServiceProcess.ServiceController(name);
            var want = start ? System.ServiceProcess.ServiceControllerStatus.Running : System.ServiceProcess.ServiceControllerStatus.Stopped;
            if (sc.Status != want)
            {
                if (start) sc.Start(); else sc.Stop();
                sc.WaitForStatus(want, TimeSpan.FromSeconds(60));
            }
            if (!start)
            {
                // The process may still hold the database for a moment after the service reports stopped
                for (var i = 0; i < 20 && Process.GetProcessesByName("FileAccessMonitor").Any(p => p.Id != Environment.ProcessId && IsService(p)); i++)
                    Thread.Sleep(500);
            }
            return true;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ServiceProcess.TimeoutException) { return false; }
    }

    // A FileAccessMonitor process in session 0 (a service), not another command line like this one
    private static bool IsService(Process p)
    {
        try { return p.SessionId == 0; } catch { return false; }
    }

    private static int RunTool(string file, string arguments)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(file, arguments) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true });
            if (p == null) return -1;
            p.WaitForExit(120_000);
            return p.HasExited ? p.ExitCode : -1;
        }
        catch (System.ComponentModel.Win32Exception) { return -1; }
    }

    private static bool IsElevated()
    {
        if (OperatingSystem.IsWindows())
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return identity.IsSystem || new System.Security.Principal.WindowsPrincipal(identity)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        return SecretStore.IsLinuxRoot();
    }

    public static string Size(long bytes) => bytes switch
    {
        >= 1L << 30 => $"{bytes / (double)(1L << 30):0.0} GB",
        >= 1L << 20 => $"{bytes / (double)(1L << 20):0.0} MB",
        >= 1L << 10 => $"{bytes / 1024.0:0} KB",
        _ => $"{bytes} B",
    };
}
