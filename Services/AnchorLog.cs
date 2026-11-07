using System.Diagnostics;
using System.Runtime.InteropServices;

namespace FileAccessMonitor.Services;

// Writes the daily anchor line to the operating system log, which an administrator can forward off the machine:
// Windows Application event log (source FileAccessMonitor, event id 1100), Linux syslog / journald (tag fileaccessmonitor).
// Never throws. Creating the event source needs administrator rights: the installer does it (the service runs as an unprivileged
// account since 1.11 and cannot, and checking for a source it cannot find may throw a SecurityException for
// it); when the source is missing, the entry goes to the Application log under the source "Application".
public static class AnchorLog
{
    public const string Source = "FileAccessMonitor";
    public const int EventId = 1100;

    private static string? _windowsSource;
    private static IntPtr _syslogIdent;

    public static void Write(string line, ILogger? logger = null)
    {
        try
        {
            if (OperatingSystem.IsWindows()) WriteWindows(line, logger);
            else if (OperatingSystem.IsLinux()) WriteLinux(line);
        }
        catch (Exception ex)
        {
            logger?.LogWarning(ex, "The anchor line could not be written to the system log.");
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void WriteWindows(string line, ILogger? logger)
    {
        _windowsSource ??= ResolveWindowsSource(logger);
        EventLog.WriteEntry(_windowsSource, line, EventLogEntryType.Information, EventId);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string ResolveWindowsSource(ILogger? logger)
    {
        try
        {
            if (EventLog.SourceExists(Source)) return Source;
            EventLog.CreateEventSource(Source, "Application");   // needs administrator rights (not the service account)
            return Source;
        }
        catch (Exception ex)
        {
            logger?.LogWarning("The event log source {Source} does not exist and cannot be created ({Reason}); anchors are written as source Application. " +
                "Run the installer again, or create it once as administrator: New-EventLog -LogName Application -Source {Source}", Source, ex.GetType().Name, Source);
            return "Application";
        }
    }

    private const int LogNotice = 5;
    private const int LogLocal5 = 21 << 3;
    private const int LogPid = 1;

    [DllImport("libc", EntryPoint = "openlog")]
    private static extern void OpenLog(IntPtr ident, int option, int facility);

    [DllImport("libc", EntryPoint = "syslog")]
    private static extern void SysLog(int priority, string format, string message);

    private static void WriteLinux(string line)
    {
        if (_syslogIdent == IntPtr.Zero)
        {
            _syslogIdent = Marshal.StringToHGlobalAnsi("fileaccessmonitor");   // openlog keeps the pointer
            OpenLog(_syslogIdent, LogPid, LogLocal5);
        }
        SysLog(LogLocal5 | LogNotice, "%s", line);
    }
}
