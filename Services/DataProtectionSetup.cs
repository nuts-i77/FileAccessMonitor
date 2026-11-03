using Microsoft.AspNetCore.DataProtection;

namespace FileAccessMonitor.Services;

// ASP.NET Core Data Protection as the web application sets it up (Program.cs), so the command line
// can protect secrets that the service later reads (the password of a web GUI certificate).
// On Windows the keys are encrypted with the machine's DPAPI; on Linux they rely on the data
// folder being readable by the service account only.
public static class DataProtectionSetup
{
    public const string ApplicationName = "FileAccessMonitor";

    public static string KeysDirectory => Path.Combine(AppPaths.DataDir, "keys");

    public static IDataProtectionBuilder Configure(IDataProtectionBuilder builder)
    {
        builder.SetApplicationName(ApplicationName).PersistKeysToFileSystem(new DirectoryInfo(KeysDirectory));
        if (OperatingSystem.IsWindows())
            builder.ProtectKeysWithDpapi(protectToLocalMachine: true);
        return builder;
    }

    public static IDataProtectionProvider CreateProvider() =>
        DataProtectionProvider.Create(new DirectoryInfo(KeysDirectory), options =>
        {
            options.SetApplicationName(ApplicationName);
            if (OperatingSystem.IsWindows())
                options.ProtectKeysWithDpapi(protectToLocalMachine: true);
        });
}
