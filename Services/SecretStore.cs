using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace FileAccessMonitor.Services;

// Secrets generated on first run, stored under ProgramData with an ACL that
// only SYSTEM and Administrators can read.
public static class SecretStore
{
    private static readonly string DataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "FileAccessMonitor");

    private static readonly string JwtKeyFile = Path.Combine(DataDir, "jwt.key");

    public static readonly string InitialAdminPasswordFile =
        Path.Combine(DataDir, "initial-admin-password.txt");

    public static string GetOrCreateJwtKey()
    {
        if (File.Exists(JwtKeyFile))
        {
            string existing;
            try { existing = File.ReadAllText(JwtKeyFile).Trim(); }
            catch (UnauthorizedAccessException ex)
            {
                throw new InvalidOperationException(
                    $"Cannot read {JwtKeyFile}. Run FileAccessMonitor as the Windows service (LocalSystem) or from an elevated (Administrator) prompt.", ex);
            }
            if (existing.Length >= 32) return existing;
        }

        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        WriteProtected(JwtKeyFile, key);
        return key;
    }

    public static string CreateInitialAdminPassword()
    {
        const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
        var password = RandomNumberGenerator.GetString(chars, 16);
        WriteProtected(InitialAdminPasswordFile, password + Environment.NewLine);
        return password;
    }

    public static void DeleteInitialAdminPassword()
    {
        try { File.Delete(InitialAdminPasswordFile); } catch { }
    }

    private static void WriteProtected(string path, string content)
    {
        Directory.CreateDirectory(DataDir);
        if (File.Exists(path)) File.Delete(path);

        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(sid, null), FileSystemRights.FullControl, AccessControlType.Allow));

        using var fs = new FileInfo(path).Create(
            FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None,
            4096, FileOptions.None, security);
        using var writer = new StreamWriter(fs);
        writer.Write(content);
    }
}
