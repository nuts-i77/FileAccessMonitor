namespace FileAccessMonitor.Services;

// Where settings, records, keys, and logs live: C:\ProgramData\FileAccessMonitor, or the folder in
// the FILEACCESSMONITOR_DATA environment variable (for development and demos, so a second
// instance does not touch the installed one).
public static class AppPaths
{
    public static readonly string DataDir =
        Environment.GetEnvironmentVariable("FILEACCESSMONITOR_DATA") is { Length: > 0 } dir
            ? Path.GetFullPath(dir)
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FileAccessMonitor");
}
