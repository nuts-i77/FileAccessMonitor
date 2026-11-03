using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace FileAccessMonitor.Services;

// Secrets generated on first run, stored under ProgramData with an ACL that
// only SYSTEM and Administrators can read.
public static class SecretStore
{
    private static readonly string DataDir = AppPaths.DataDir;

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

    private static readonly string ChainKeyFile = Path.Combine(DataDir, "chain.key");
    private static byte[]? _chainKey;

    // The HMAC key of the tamper-detection chains: 32 random bytes, kept outside the database.
    // Back it up with the data folder; without it old records cannot be verified.
    public static byte[] GetOrCreateChainKey()
    {
        if (_chainKey != null) return _chainKey;
        if (File.Exists(ChainKeyFile))
        {
            byte[] existing;
            try { existing = File.ReadAllBytes(ChainKeyFile); }
            catch (UnauthorizedAccessException ex)
            {
                throw new InvalidOperationException(
                    $"Cannot read {ChainKeyFile}. Run FileAccessMonitor as the Windows service (LocalSystem) or from an elevated (Administrator) prompt.", ex);
            }
            if (existing.Length == 32) return _chainKey = existing;
        }

        var key = RandomNumberGenerator.GetBytes(32);
        WriteProtected(ChainKeyFile, key);
        return _chainKey = key;
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

    internal static void WriteProtected(string path, string content) =>
        WriteProtected(path, new System.Text.UTF8Encoding(false).GetBytes(content));

    // Readable by SYSTEM and Administrators only (on Linux: by the service account only)
    internal static void WriteProtected(string path, byte[] content)
    {
        Directory.CreateDirectory(DataDir);
        if (File.Exists(path)) File.Delete(path);

        if (!OperatingSystem.IsWindows())
        {
            using var unixFile = new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            });
            unixFile.Write(content);
            return;
        }

        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(sid, null), FileSystemRights.FullControl, AccessControlType.Allow));

        using var fs = new FileInfo(path).Create(
            FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None,
            4096, FileOptions.None, security);
        fs.Write(content);
    }
}
