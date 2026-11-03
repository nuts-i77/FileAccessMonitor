using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FileAccessMonitor.Services;

// The HTTPS port agents connect to. Its certificate is self-signed, created on first start and kept
// in the machine certificate store (on Linux: a PFX file in the data folder, readable by the service
// account only); agents trust it by its fingerprint, which the registration code carries, so no
// certificate authority is needed. It is independent of the web GUI's certificate (WebTls), and must
// never change on its own: subject, names and validity below stay as they were.
public static class AgentEndpoint
{
    public const int DefaultPort = 8443;
    internal const string Subject = "CN=FileAccessMonitor Agent Endpoint";
    internal const string PfxFileName = "agent-endpoint.pfx";
    internal const int ValidityYears = 20;

    public static int Port(IConfiguration config) => config.GetValue("Agents:Port", DefaultPort);

    // On unless "Agents": { "Enabled": false } is set in settings.json
    public static bool Enabled(IConfiguration config) => config.GetValue("Agents:Enabled", true);

    // Set at startup; null when the certificate could not be created (e.g. not running elevated)
    public static X509Certificate2? Certificate { get; private set; }

    // Whether this run set up the agent port
    public static bool Active { get; private set; }

    public static X509Certificate2? Initialize(Serilog.ILogger log)
    {
        Active = true;
        try
        {
            Certificate = SelfSignedCertificate.LoadOrCreate(Subject, PfxFileName, Names(), ValidityYears, IsUsable, log, "agent endpoint");
            return Certificate;
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException or IOException)
        {
            log.Warning(ex, "Could not set up the agent endpoint certificate; agents cannot connect. Run as the service (LocalSystem) or elevated.");
            return null;
        }
    }

    internal static string[] Names() => [Environment.MachineName];

    internal static bool IsUsable(X509Certificate2 cert) => cert.HasPrivateKey && cert.NotAfter > DateTime.Now.AddDays(30);
}
