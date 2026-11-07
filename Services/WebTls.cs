using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.DataProtection;

namespace FileAccessMonitor.Services;

// "Web": { "Https": { ... } } in settings.json
public record WebTlsSettings(bool Enabled, string Mode, string PfxFile, string? PfxPassword, int RedirectPort)
{
    public const string SelfSignedMode = "SelfSigned";
    public const string PfxMode = "Pfx";

    public bool UsesPfx => Mode.Equals(PfxMode, StringComparison.OrdinalIgnoreCase);

    public static WebTlsSettings Parse(JsonObject root)
    {
        var node = root["Web"]?["Https"] as JsonObject;
        var mode = node?["Mode"]?.GetValue<string>() ?? SelfSignedMode;
        return new WebTlsSettings(
            node?["Enabled"] is JsonValue e && e.TryGetValue<bool>(out var enabled) && enabled,
            mode.Equals(PfxMode, StringComparison.OrdinalIgnoreCase) ? PfxMode : SelfSignedMode,
            node?["PfxFile"]?.GetValue<string>() ?? WebTls.UserPfxFileName,
            node?["PfxPassword"]?.GetValue<string>(),
            node?["RedirectPort"] is JsonValue r && r.TryGetValue<int>(out var port) && port is > 0 and <= 65535 ? port : 0);
    }

    public static WebTlsSettings Load() => Parse(SettingsStore.Load());
}

// What the running service serves (GET /api/web-tls)
public record WebTlsStatus(bool Https, string? Mode, string? Subject, IReadOnlyList<string> Names, string? Fingerprint,
    DateTime? NotAfter)
{
    public static readonly WebTlsStatus Off = new(false, null, null, [], null, null);
}

// HTTPS for the web GUI: a self-signed certificate that covers the machine's names and addresses
// (made again when one is missing), or a PFX file of the administrator's. The same port as before
// switches to TLS; the agent port and its certificate are separate (AgentEndpoint).
public static class WebTls
{
    public const string Subject = "CN=FileAccessMonitor Web GUI";
    public const string SelfSignedPfxFileName = "web-https.pfx";
    public const string UserPfxFileName = "web-user.pfx";
    public const string PasswordPurpose = "FileAccessMonitor.WebTls";
    public const string PasswordPrefix = "enc:";
    private const int ValidityYears = 10;

    // Set at startup
    public static WebTlsStatus Status { get; private set; } = WebTlsStatus.Off;

    // The certificate for the web GUI port, or null (off, or it could not be loaded: the GUI then
    // stays reachable over HTTP and the log says why)
    public static X509Certificate2? Initialize(WebTlsSettings settings, Serilog.ILogger log, IDataProtectionProvider? dataProtection = null)
    {
        Status = WebTlsStatus.Off;
        if (!settings.Enabled) return null;
        try
        {
            X509Certificate2 cert;
            string mode;
            if (settings.UsesPfx)
            {
                cert = LoadUserPfx(settings, dataProtection ?? DataProtectionSetup.CreateProvider());
                mode = "pfx";
                if (cert.NotAfter < DateTime.Now) log.Warning("The web GUI certificate expired on {NotAfter:yyyy-MM-dd}.", cert.NotAfter);
            }
            else
            {
                var wanted = CurrentNames();
                cert = SelfSignedCertificate.LoadOrCreate(Subject, SelfSignedPfxFileName, wanted, ValidityYears,
                    c => IsUsable(c, wanted), log, "web GUI", replaceStale: true);
                mode = "selfSigned";
            }
            Status = new WebTlsStatus(true, mode, cert.Subject, SelfSignedCertificate.Names(cert), AgentSecrets.Fingerprint(cert), cert.NotAfter.ToUniversalTime());
            log.Information("The web GUI uses HTTPS ({Mode} certificate, SHA-256 {Fingerprint}).", mode, Status.Fingerprint);
            return cert;
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException or IOException or InvalidOperationException)
        {
            log.Warning(ex, "Could not load the web GUI certificate; the web GUI uses HTTP instead. Fix it or run: FileAccessMonitor web-https off");
            return null;
        }
    }

    // A stored self-signed certificate is kept while it has a private key, is valid for 30 more days
    // and covers every name and address the machine has now
    internal static bool IsUsable(X509Certificate2 cert, IReadOnlyCollection<string> wanted) =>
        cert.HasPrivateKey && cert.NotAfter > DateTime.Now.AddDays(30) && !NeedsNewCertificate(SelfSignedCertificate.Names(cert), wanted);

    // A name or address the certificate does not have yet (the machine was renamed or got an address)
    public static bool NeedsNewCertificate(IEnumerable<string> certificateNames, IEnumerable<string> wanted)
    {
        var have = new HashSet<string>(certificateNames, StringComparer.OrdinalIgnoreCase);
        return wanted.Any(w => !have.Contains(w));
    }

    // The names and addresses the web GUI certificate should cover
    public static IReadOnlyList<string> CurrentNames()
    {
        string? fqdn = null;
        try { fqdn = Dns.GetHostEntry(Environment.MachineName).HostName; } catch (SocketException) { }
        var ips = new List<IPAddress>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                         .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
            foreach (var address in nic.GetIPProperties().UnicastAddresses)
            {
                // Temporary IPv6 addresses change every day; they would renew the certificate each time
                // (on Linux the framework cannot tell them apart, so IPv6 addresses are left out)
                if (address.Address.AddressFamily == AddressFamily.InterNetworkV6
                    && (!OperatingSystem.IsWindows() || address.SuffixOrigin == SuffixOrigin.Random)) continue;
                ips.Add(address.Address);
            }
        }
        catch (NetworkInformationException) { }
        return BuildNames(Environment.MachineName, fqdn, ips);
    }

    // Machine name, FQDN, localhost, the addresses (not link-local ones) and the loopback addresses
    public static IReadOnlyList<string> BuildNames(string machine, string? fqdn, IEnumerable<IPAddress> addresses)
    {
        var names = new List<string> { machine };
        if (!string.IsNullOrWhiteSpace(fqdn)) names.Add(fqdn.TrimEnd('.'));
        names.Add("localhost");
        foreach (var a in addresses)
        {
            if (a.IsIPv6LinkLocal || a.IsIPv6Multicast || a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any)) continue;
            var ip = new IPAddress(a.GetAddressBytes()); // without the zone (scope) id
            names.Add(ip.ToString());
        }
        names.Add("127.0.0.1");
        names.Add("::1");
        return names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    // "http://0.0.0.0:8080" -> "https://0.0.0.0:8080" (also several URLs separated by ;)
    public static string ToHttps(string urls) =>
        string.Join(';', urls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(u => u.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ? "https://" + u[7..] : u));

    // The port of the first URL, or null
    public static int? PortOf(string urls)
    {
        var first = urls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
        return first != null && Uri.TryCreate(first.Replace("://*", "://localhost").Replace("://+", "://localhost").Replace("://0.0.0.0", "://localhost"), UriKind.Absolute, out var uri)
            ? uri.Port : null;
    }

    private static X509Certificate2 LoadUserPfx(WebTlsSettings settings, IDataProtectionProvider dataProtection)
    {
        var file = Path.Combine(AppPaths.DataDir, Path.GetFileName(settings.PfxFile));
        var password = UnprotectPassword(settings.PfxPassword, dataProtection);
        // The service account cannot add to the machine store, and does not need to: the key is loaded
        // into the machine key set for the life of the process (see SelfSignedCertificate)
        var cert = X509CertificateLoader.LoadPkcs12FromFile(file, password, SelfSignedCertificate.LoadFlags);
        if (!cert.HasPrivateKey) throw new CryptographicException($"{file} has no private key.");
        return cert;
    }

    public static string? ProtectPassword(string? password, IDataProtectionProvider dataProtection) =>
        string.IsNullOrEmpty(password) ? null : PasswordPrefix + dataProtection.CreateProtector(PasswordPurpose).Protect(password);

    public static string? UnprotectPassword(string? stored, IDataProtectionProvider dataProtection) =>
        string.IsNullOrEmpty(stored) ? null
        : stored.StartsWith(PasswordPrefix, StringComparison.Ordinal)
            ? dataProtection.CreateProtector(PasswordPurpose).Unprotect(stored[PasswordPrefix.Length..])
            : stored;

    // Checks a PFX an administrator supplied: it must open with the password, have a private key and
    // not be expired
    public static X509Certificate2 ReadPfx(byte[] data, string? password)
    {
        X509Certificate2 cert;
        try { cert = X509CertificateLoader.LoadPkcs12(data, password, X509KeyStorageFlags.Exportable); }
        catch (CryptographicException ex) { throw new InvalidOperationException("The PFX file could not be opened (wrong password or not a PFX file): " + ex.Message, ex); }
        if (!cert.HasPrivateKey) throw new InvalidOperationException("The PFX file has no private key.");
        if (cert.NotAfter < DateTime.Now) throw new InvalidOperationException($"The certificate expired on {cert.NotAfter:yyyy-MM-dd}.");
        return cert;
    }

    public static string Describe(X509Certificate2 cert)
    {
        var names = SelfSignedCertificate.Names(cert);
        return $"Subject: {cert.Subject}{Environment.NewLine}Names: {(names.Count > 0 ? string.Join(", ", names) : "(none)")}{Environment.NewLine}" +
               $"Expires: {cert.NotAfter:yyyy-MM-dd}{Environment.NewLine}SHA-256: {AgentSecrets.Fingerprint(cert)}";
    }

    // FileAccessMonitor web-https on|off|status [--pfx file --pfx-password pw | --pfx-password-file f] [--redirect-port n]
    // Takes effect when the service starts.
    public static int RunCommand(string[] args, TextWriter output, TextWriter error, IDataProtectionProvider? dataProtection = null,
        string? settingsFile = null)
    {
        var file = settingsFile ?? SettingsStore.DefaultPath;
        const string usage = "Usage: FileAccessMonitor web-https on|off|status [--pfx <file> [--pfx-password <pw> | --pfx-password-file <file>]] [--redirect-port <port>]";
        if (args.Length < 2 || args[1] is not ("on" or "off" or "status")) { error.WriteLine(usage); return 2; }
        var action = args[1];

        string? pfx = null, password = null;
        int? redirect = null;
        var keep = false; // "on" without --pfx keeps the certificate setting as it is (to change only the redirect port)
        for (var i = 2; i < args.Length; i++)
        {
            string Value() => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"{args[i]} needs a value.");
            try
            {
                switch (args[i])
                {
                    case "--keep": keep = true; break;
                    case "--pfx": pfx = Value(); break;
                    case "--pfx-password": password = Value(); break;
                    case "--pfx-password-file": password = File.ReadLines(Value()).FirstOrDefault() ?? ""; break;
                    case "--redirect-port":
                        if (!int.TryParse(Value(), out var port) || port is < 0 or > 65535) { error.WriteLine("--redirect-port needs a port number (0 = none)."); return 2; }
                        redirect = port;
                        break;
                    default: error.WriteLine($"Unknown option {args[i]}. {usage}"); return 2;
                }
            }
            catch (Exception ex) when (ex is ArgumentException or IOException) { error.WriteLine(ex.Message); return 2; }
        }

        var current = WebTlsSettings.Parse(SettingsStore.Load(file));
        if (action == "status")
        {
            output.WriteLine(current.Enabled ? "on" : "off");
            output.WriteLine($"mode: {current.Mode}");
            output.WriteLine($"redirect port: {current.RedirectPort}");
            return 0;
        }

        if (action == "off")
        {
            SettingsStore.Update(file, root =>
            {
                Settings(root)["Enabled"] = false;
                if (redirect != null) Settings(root)["RedirectPort"] = redirect.Value;
            });
            output.WriteLine("HTTPS for the web GUI: off. Restart the service to apply.");
            return 0;
        }

        dataProtection ??= DataProtectionSetup.CreateProvider();
        string? storedPassword = null;
        if (pfx != null)
        {
            X509Certificate2 cert;
            byte[] data;
            try
            {
                data = File.ReadAllBytes(pfx);
                cert = ReadPfx(data, password);
            }
            catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
            {
                error.WriteLine(ex.Message);
                return 1;
            }
            using (cert)
            {
                SecretStore.WriteProtected(Path.Combine(AppPaths.DataDir, UserPfxFileName), data);
                storedPassword = ProtectPassword(password, dataProtection);
                output.WriteLine(Describe(cert));
                var hosts = CurrentNames().Where(n => !IPAddress.TryParse(n, out _) && n != "localhost").ToList();
                if (!SelfSignedCertificate.Names(cert).Concat([cert.GetNameInfo(X509NameType.DnsName, false)])
                        .Any(n => hosts.Any(h => MatchesName(n, h))))
                    output.WriteLine($"Warning: no name in the certificate matches this machine ({string.Join(", ", hosts)}); browsers will warn.");
            }
        }

        SettingsStore.Update(file, root =>
        {
            var node = Settings(root);
            node["Enabled"] = true;
            if (pfx != null)
            {
                node["Mode"] = WebTlsSettings.PfxMode;
                node["PfxFile"] = UserPfxFileName;
                node["PfxPassword"] = storedPassword;
            }
            else if (!keep)
            {
                node["Mode"] = WebTlsSettings.SelfSignedMode;
                node.Remove("PfxFile");
                node.Remove("PfxPassword");
            }
            if (redirect != null) node["RedirectPort"] = redirect.Value;
        });
        if (pfx == null && !keep)
        {
            try { File.Delete(Path.Combine(AppPaths.DataDir, UserPfxFileName)); } catch (IOException) { }
        }
        output.WriteLine($"HTTPS for the web GUI: on ({(pfx != null || (keep && current.UsesPfx) ? "your certificate" : "self-signed certificate")}). Restart the service to apply.");
        return 0;
    }

    // Exact name, or a wildcard certificate name (*.example.com) for a host in that domain
    internal static bool MatchesName(string? certificateName, string host)
    {
        if (string.IsNullOrEmpty(certificateName)) return false;
        if (certificateName.Equals(host, StringComparison.OrdinalIgnoreCase)) return true;
        if (certificateName.StartsWith("*.", StringComparison.Ordinal))
            return host.Contains('.') && host[host.IndexOf('.')..].Equals(certificateName[1..], StringComparison.OrdinalIgnoreCase);
        return false;
    }

    private static JsonObject Settings(JsonObject root)
    {
        var web = root["Web"] as JsonObject ?? (JsonObject)(root["Web"] = new JsonObject());
        return web["Https"] as JsonObject ?? (JsonObject)(web["Https"] = new JsonObject());
    }
}
