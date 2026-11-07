namespace FileAccessMonitor.Services;

// Where settings, records, keys, and logs live: C:\ProgramData\FileAccessMonitor
// (/var/lib/fileaccessmonitor for the Linux agent), or the folder in the FILEACCESSMONITOR_DATA
// environment variable (for development and demos, so a second instance does not touch the
// installed one).
//
// The privileged collector (FileAccessMonitor collector, see CollectorHost) keeps its own state in
// the "collector" subfolder, which the web process cannot read; DataDir is that folder in the
// collector process, so everything that stores something there (settings, outbox, logs) lands in it
// without further changes. BaseDataDir is always the server's data folder.
public static class AppPaths
{
    public const string CollectorFolderName = "collector";

    public static readonly bool CollectorMode =
        Environment.GetCommandLineArgs().Skip(1).FirstOrDefault() == "collector";

    public static readonly string BaseDataDir =
        Environment.GetEnvironmentVariable("FILEACCESSMONITOR_DATA") is { Length: > 0 } dir
            ? Path.GetFullPath(dir)
            : OperatingSystem.IsWindows()
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FileAccessMonitor")
                : "/var/lib/fileaccessmonitor";

    public static readonly string DataDir =
        CollectorMode ? Path.Combine(BaseDataDir, CollectorFolderName) : BaseDataDir;
}
