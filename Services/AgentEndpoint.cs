using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FileAccessMonitor.Services;

// The HTTPS port agents connect to. Its certificate is self-signed, created on first start and kept
// in the machine certificate store; agents trust it by its fingerprint, which the registration
// code carries, so no certificate authority is needed.
public static class AgentEndpoint
{
    public const int DefaultPort = 8443;
    private const string Subject = "CN=FileAccessMonitor Agent Endpoint";

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
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            var existing = store.Certificates
                .Find(X509FindType.FindBySubjectDistinguishedName, Subject, validOnly: false)
                .Where(c => c.HasPrivateKey && c.NotAfter > DateTime.Now.AddDays(30))
                .OrderByDescending(c => c.NotAfter)
                .FirstOrDefault();
            if (existing != null) return Certificate = existing;

            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest(Subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                [new Oid("1.3.6.1.5.5.7.3.1")], critical: false)); // server authentication
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(Environment.MachineName);
            request.CertificateExtensions.Add(san.Build());
            using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(20));

            // Re-import so the private key is persisted in the machine key store (Kestrel needs that)
            var cert = X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pfx), null,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
            store.Add(cert);
            log.Information("Created the agent endpoint certificate (SHA-256 {Fingerprint}).", AgentSecrets.Fingerprint(cert));
            return Certificate = cert;
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException)
        {
            log.Warning(ex, "Could not set up the agent endpoint certificate; agents cannot connect. Run as the service (LocalSystem) or elevated.");
            return null;
        }
    }
}
