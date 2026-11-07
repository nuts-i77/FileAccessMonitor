using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FileAccessMonitor.Services;

// The HTTPS port agents connect to. Its certificate is self-signed, created on first start and kept
// as a PFX file in the data folder, readable by the service account only (older versions kept it in
// the machine certificate store on Windows; SelfSignedCertificate still uses such a certificate, so
// its fingerprint stays); agents trust it by its fingerprint, which the registration code carries, so no
// certificate authority is needed. It is independent of the web GUI's certificate (WebTls), and must
// never change on its own: subject, names and validity below stay as they were.
// The local collector (LocalCollector) uses the same port over loopback, also when agents are turned off.
public static class AgentEndpoint
{
    public const int DefaultPort = 8443;
    internal const string Subject = "CN=FileAccessMonitor Agent Endpoint";
    internal const string PfxFileName = "agent-endpoint.pfx";
    internal const int ValidityYears = 20;

    public static int Port(IConfiguration config) => config.GetValue("Agents:Port", DefaultPort);

    // On unless "Agents": { "Enabled": false } is set in settings.json
    public static bool Enabled(IConfiguration config) => config.GetValue("Agents:Enabled", true);

    // Set at startup; null when the certificate could not be created
    public static X509Certificate2? Certificate { get; private set; }

    // Whether this run set up the agent port for agents (not just for the local collector on loopback)
    public static bool Active { get; private set; }

    public static X509Certificate2? Initialize(Serilog.ILogger log, bool forAgents = true)
    {
        Active = forAgents;
        try
        {
            Certificate = SelfSignedCertificate.LoadOrCreate(Subject, PfxFileName, Names(), ValidityYears, IsUsable, log, "agent endpoint");
            return Certificate;
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException or IOException)
        {
            log.Warning(ex, "Could not set up the agent endpoint certificate; agents and the local collector cannot connect. Check that the service account can read and write the data folder.");
            return null;
        }
    }

    internal static string[] Names() => [Environment.MachineName];

    internal static bool IsUsable(X509Certificate2 cert) => cert.HasPrivateKey && cert.NotAfter > DateTime.Now.AddDays(30);

    // For the collector (privileged, a separate process): the fingerprint of the certificate that the web
    // part serves on the agent port, read the way the web part picks it (the file first, then, on Windows,
    // a certificate an earlier version left in the machine store). null until the web part has made it.
    public static string? ReadFingerprint(string? dataDir = null)
    {
        try
        {
            var file = Path.Combine(dataDir ?? AppPaths.BaseDataDir, PfxFileName);
            if (File.Exists(file))
            {
                using var cert = X509CertificateLoader.LoadPkcs12FromFile(file, null, X509KeyStorageFlags.EphemeralKeySet);
                if (IsUsable(cert)) return AgentSecrets.Fingerprint(cert);
            }
            if (SelfSignedCertificate.FindInMachineStore(Subject, IsUsable) is { } legacy)
                using (legacy) return AgentSecrets.Fingerprint(legacy);
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException) { }
        return null;
    }
}
