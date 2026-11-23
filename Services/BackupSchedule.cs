using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace FileAccessMonitor.Services;

// The daily backup, set up by an administrator with "backup-schedule" (also run by the installers):
//   Windows: a Task Scheduler task "FileAccessMonitor Backup" that runs "backup --reason scheduled" as SYSTEM
//   Linux:   fileaccessmonitor-backup.service and .timer in /etc/systemd/system, run as root
// The schedule lives in the task or timer, which only administrators can change: the web service, which can
// write settings.json, must not be able to choose where SYSTEM writes the keys. backup-schedule.json in the
// data folder only tells the web GUI what was set up (it is not read by the backup itself).
public static class BackupSchedule
{
    public const string TaskName = "FileAccessMonitor Backup";
    public const string InfoFile = "backup-schedule.json";
    public const string LinuxUnit = "fileaccessmonitor-backup";
    public const string LinuxUnitDir = "/etc/systemd/system";
    public const string DefaultTime = "02:00";
    public const int DefaultKeep = 7;

    // Windows limits a task's command line to 261 characters
    private const int MaxTaskCommand = 261;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    private static readonly string Usage =
        "Usage:\n" +
        "  FileAccessMonitor backup-schedule                                  show the daily backup\n" +
        "  FileAccessMonitor backup-schedule [--time HH:MM] [--keep N] [--to <folder>]   set it up or change it\n" +
        "  FileAccessMonitor backup-schedule --off                            stop it\n" +
        $"Defaults: --time {DefaultTime}, --keep {DefaultKeep}, the data folder's backups folder.";

    public static BackupScheduleInfo? Read(string dataDir)
    {
        try
        {
            var file = Path.Combine(dataDir, InfoFile);
            return File.Exists(file) ? JsonSerializer.Deserialize<BackupScheduleInfo>(File.ReadAllText(file), JsonOptions) : null;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException) { return null; }
    }

    public static int Run(string[] args, string dataDir, string exe, TextWriter output, TextWriter error)
    {
        string? time = null, to = null;
        int? keep = null;
        var off = false;
        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--time" when i + 1 < args.Length: time = args[++i]; break;
                case "--keep" when i + 1 < args.Length && int.TryParse(args[i + 1], out var k): keep = k; i++; break;
                case "--to" when i + 1 < args.Length: to = args[++i]; break;
                case "--off": off = true; break;
                case "-h" or "--help": output.WriteLine(Usage); return 0;
                default:
                    error.WriteLine($"Unknown argument: {args[i]}");
                    error.WriteLine(Usage);
                    return 2;
            }
        }

        var current = Read(dataDir);
        if (args.Length == 1)
        {
            Show(current, output);
            return 0;
        }
        if (off)
        {
            if (!Remove(error)) return 1;
            Write(dataDir, new BackupScheduleInfo(false, current?.Time ?? DefaultTime, current?.Keep ?? DefaultKeep, current?.To, DateTime.UtcNow));
            output.WriteLine("The daily backup is off. Backups already made are kept.");
            return 0;
        }

        // Unspecified options keep what was set before
        time ??= current?.Time ?? DefaultTime;
        keep ??= current?.Keep ?? DefaultKeep;
        if (to == null && current?.Enabled == true) to = current.To;
        if (to is { Length: 0 }) to = null;   // --to "" goes back to the data folder's backups folder

        if (!TimeOk(time)) { error.WriteLine("--time takes HH:MM, for example 02:00."); return 2; }
        time = TimeSpan.Parse(time).ToString(@"hh\:mm");
        if (keep is < 1 or > 365) { error.WriteLine("--keep takes 1 to 365."); return 2; }
        if (to != null)
        {
            to = Path.GetFullPath(to);
            if (DataBackup.CheckFolder(dataDir, to) is { } problem)
            {
                error.WriteLine(Messages.Get(problem, to));
                return 1;
            }
            if (!OperatingSystem.IsWindows() && !LinuxPathOk(to))
            {
                error.WriteLine("On Linux the folder name may not contain quotes, backslashes, % or spaces.");
                return 2;
            }
        }

        if (!Install(exe, time, keep.Value, to, error)) return 1;
        var info = new BackupScheduleInfo(true, time, keep.Value, to, DateTime.UtcNow);
        Write(dataDir, info);
        output.WriteLine("The daily backup is set up:");
        Show(info, output);
        if (to != null && OperatingSystem.IsWindows() && to.StartsWith(@"\\", StringComparison.Ordinal))
            output.WriteLine("The task runs as SYSTEM, which reaches a share as this computer's account (DOMAIN\\" +
                             Environment.MachineName + "$): allow that account to modify the share folder.");
        return 0;
    }

    private static void Show(BackupScheduleInfo? info, TextWriter output)
    {
        if (info is not { Enabled: true })
        {
            output.WriteLine("The daily backup is not set up. Set it up with: FileAccessMonitor backup-schedule --time 02:00 --keep 7");
            return;
        }
        output.WriteLine($"  Every day at {info.Time}, keeping the last {info.Keep}, in {info.To ?? "the data folder's backups folder"}");
        output.WriteLine(OperatingSystem.IsWindows()
            ? $"  Task Scheduler: \"{TaskName}\" (runs as SYSTEM)"
            : $"  systemd: {LinuxUnit}.timer (systemctl list-timers {LinuxUnit}.timer)");
    }

    private static void Write(string dataDir, BackupScheduleInfo info) =>
        SecretStore.WriteProtected(Path.Combine(dataDir, InfoFile), JsonSerializer.Serialize(info, JsonOptions));

    internal static bool TimeOk(string time) =>
        Regex.IsMatch(time, @"^([01]?\d|2[0-3]):[0-5]\d$");

    internal static bool LinuxPathOk(string path) => !Regex.IsMatch(path, "[\"'\\\\%\\s]");

    // ---------------------------------------------------------------- what is installed

    // The arguments of the scheduled backup (after the program)
    // A folder ending in a backslash (D:\) gets another one: before a closing quote two read as one, one would
    // escape the quote
    internal static string BackupArguments(int keep, string? to) =>
        $"backup --reason {DataBackup.ReasonScheduled} --keep {keep}"
        + (to != null ? $" --to \"{(to.EndsWith('\\') ? to + "\\" : to)}\"" : "");

    internal static string WindowsTaskCommand(string exe, int keep, string? to) => $"\"{exe}\" {BackupArguments(keep, to)}";

    internal static string LinuxService(string exe, int keep, string? to) =>
        "# Written by: FileAccessMonitor backup-schedule (change it with that command)\n" +
        "[Unit]\n" +
        "Description=FileAccessMonitor daily backup of the data folder\n" +
        "\n" +
        "[Service]\n" +
        "Type=oneshot\n" +
        $"ExecStart=\"{exe}\" {BackupArguments(keep, to)}\n";

    internal static string LinuxTimer(string time) =>
        "# Written by: FileAccessMonitor backup-schedule (change it with that command)\n" +
        "[Unit]\n" +
        "Description=FileAccessMonitor daily backup of the data folder\n" +
        "\n" +
        "[Timer]\n" +
        $"OnCalendar=*-*-* {time}:00\n" +
        // A run missed while the machine was off is made up when it starts
        "Persistent=true\n" +
        "\n" +
        "[Install]\n" +
        "WantedBy=timers.target\n";

    private static bool Install(string exe, string time, int keep, string? to, TextWriter error)
    {
        if (OperatingSystem.IsWindows())
        {
            var command = WindowsTaskCommand(exe, keep, to);
            if (command.Length > MaxTaskCommand)
            {
                error.WriteLine($"The folder name is too long for a scheduled task (the command may have {MaxTaskCommand} characters).");
                return false;
            }
            var (code, text) = Tool("schtasks.exe", ["/Create", "/TN", TaskName, "/TR", command, "/SC", "DAILY", "/ST", time,
                "/RU", "SYSTEM", "/RL", "HIGHEST", "/F"]);
            if (code != 0) { error.WriteLine($"The scheduled task could not be created: {text}"); return false; }
            return true;
        }
        try
        {
            File.WriteAllText(Path.Combine(LinuxUnitDir, LinuxUnit + ".service"), LinuxService(exe, keep, to));
            File.WriteAllText(Path.Combine(LinuxUnitDir, LinuxUnit + ".timer"), LinuxTimer(time));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"The systemd units could not be written: {ex.Message}");
            return false;
        }
        Tool("systemctl", ["daemon-reload"]);
        var (rc, output) = Tool("systemctl", ["enable", "--now", LinuxUnit + ".timer"]);
        if (rc != 0) { error.WriteLine($"The timer could not be started: {output}"); return false; }
        return true;
    }

    private static bool Remove(TextWriter error)
    {
        if (OperatingSystem.IsWindows())
        {
            if (Tool("schtasks.exe", ["/Query", "/TN", TaskName]).Code != 0) return true;   // not there
            var (code, text) = Tool("schtasks.exe", ["/Delete", "/TN", TaskName, "/F"]);
            if (code != 0) { error.WriteLine($"The scheduled task could not be deleted: {text}"); return false; }
            return true;
        }
        Tool("systemctl", ["disable", "--now", LinuxUnit + ".timer"]);
        try
        {
            File.Delete(Path.Combine(LinuxUnitDir, LinuxUnit + ".timer"));
            File.Delete(Path.Combine(LinuxUnitDir, LinuxUnit + ".service"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"The systemd units could not be removed: {ex.Message}");
            return false;
        }
        Tool("systemctl", ["daemon-reload"]);
        return true;
    }

    private static (int Code, string Text) Tool(string file, string[] arguments)
    {
        try
        {
            var start = new ProcessStartInfo(file) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var a in arguments) start.ArgumentList.Add(a);
            using var p = Process.Start(start);
            if (p == null) return (-1, "");
            var text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit(60_000);
            return (p.HasExited ? p.ExitCode : -1, text.Trim());
        }
        catch (System.ComponentModel.Win32Exception ex) { return (-1, ex.Message); }
    }
}

// What backup-schedule set up (for display; the task or timer is what runs)
public record BackupScheduleInfo(bool Enabled, string Time, int Keep, string? To, DateTime Updated);
