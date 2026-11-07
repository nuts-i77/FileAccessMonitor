using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace FileAccessMonitor.Services;

// Secrets generated on first run, stored under ProgramData with an ACL that only SYSTEM,
// Administrators and the web service account (NT SERVICE\FileAccessMonitor, which runs the web part
// without privileges) can read. The collector's own secrets (collector\ folder) are for SYSTEM and
// Administrators only.
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
                    $"Cannot read {JwtKeyFile}. Run FileAccessMonitor as the service or from an elevated (Administrator) prompt.", ex);
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
                    $"Cannot read {ChainKeyFile}. Run FileAccessMonitor as the service or from an elevated (Administrator) prompt.", ex);
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

    // Who may open a protected file
    public enum Audience
    {
        // SYSTEM, Administrators and the web service account (the secrets of the web part)
        WebService,
        // SYSTEM and Administrators only (the agent key, the collector's secrets)
        Administrators,
        // Like Administrators, and the web service account may read (collector\key.hash)
        AdministratorsWebRead,
    }

    // The Windows account the web part runs as. A virtual service account has no password; it exists
    // once the service is installed (the installer sets "obj= NT SERVICE\FileAccessMonitor").
    public const string WebServiceAccount = @"NT SERVICE\FileAccessMonitor";

    internal static void WriteProtected(string path, string content, Audience audience = Audience.WebService) =>
        WriteProtected(path, new System.Text.UTF8Encoding(false).GetBytes(content), audience);

    // Linux: readable by the owner only; the owner is the service account (the web part), or root
    // for the collector's files. A command run as root (web-https, ...) hands the file over to the
    // data folder's service account, so the service can read what the command wrote.
    internal static void WriteProtected(string path, byte[] content, Audience audience = Audience.WebService)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        if (File.Exists(path)) File.Delete(path);

        if (!OperatingSystem.IsWindows())
        {
            using (var unixFile = new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write,
                // key.hash is public by design (the web part verifies the collector with it)
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
                    | (audience == Audience.AdministratorsWebRead ? UnixFileMode.GroupRead | UnixFileMode.OtherRead : 0),
            }))
                unixFile.Write(content);
            if (audience == Audience.WebService) HandOverToServiceAccount(path);
            if (audience == Audience.AdministratorsWebRead)
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead); // a umask of 077 must not hide it
            return;
        }

        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var (sid, rights) in WindowsRules(audience))
            security.AddAccessRule(new FileSystemAccessRule(sid, rights, AccessControlType.Allow));

        using var fs = new FileInfo(path).Create(
            FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None,
            4096, FileOptions.None, security);
        fs.Write(content);
    }

    // The access rules of a protected file: SYSTEM and Administrators in full; the web service account
    // (when it exists on this machine); the account that writes the file, so that a run outside the
    // service (development, a command line as a standard user) can read its own file back.
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static List<(SecurityIdentifier Sid, FileSystemRights Rights)> WindowsRules(Audience audience)
    {
        var rules = new List<(SecurityIdentifier, FileSystemRights)>
        {
            (new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl),
            (new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl),
        };
        if (audience != Audience.Administrators && WebServiceSid() is { } web)
            rules.Add((web, audience == Audience.WebService ? FileSystemRights.FullControl : FileSystemRights.Read));
        if (WindowsIdentity.GetCurrent().User is { } self && !rules.Any(r => r.Item1 == self))
            rules.Add((self, FileSystemRights.FullControl));
        return rules;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static SecurityIdentifier? WebServiceSid()
    {
        try { return (SecurityIdentifier)new NTAccount(WebServiceAccount).Translate(typeof(SecurityIdentifier)); }
        catch (Exception ex) when (ex is IdentityNotMappedException or SystemException) { return null; }
    }

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEuid();

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "getpwnam")]
    private static extern IntPtr GetPwNam([System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPStr)] string name);

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "chown", SetLastError = true)]
    private static extern int Chown([System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPStr)] string path, uint uid, uint gid);

    private const string LinuxServiceUser = "fileaccessmonitor";

    // As root, give the file to the service account (best effort: without that user, or not as root, it stays as it is)
    private static void HandOverToServiceAccount(string path)
    {
        try
        {
            if (!OperatingSystem.IsLinux() || GetEuid() != 0) return;
            var pw = GetPwNam(LinuxServiceUser);
            if (pw == IntPtr.Zero) return;
            // struct passwd: pw_name, pw_passwd (pointers), then pw_uid, pw_gid
            var uid = (uint)System.Runtime.InteropServices.Marshal.ReadInt32(pw, 2 * IntPtr.Size);
            var gid = (uint)System.Runtime.InteropServices.Marshal.ReadInt32(pw, 2 * IntPtr.Size + 4);
            Chown(path, uid, gid);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { }
    }
}
