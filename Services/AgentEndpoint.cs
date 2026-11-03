using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FileAccessMonitor.Services;

// The HTTPS port agents connect to. Its certificate is self-signed, created on first start and kept
// in the machine certificate store (on Linux: a PFX file in the data folder, readable by the service
// account only); agents trust it by its fingerprint, which the registration code carries, so no
// certificate authority is needed.
public static class AgentEndpoint
{
    public const int DefaultPort = 8443;
    private const string Subject = "CN=FileAccessMonitor Agent Endpoint";
    private static readonly string PfxFile = Path.Combine(AppPaths.DataDir, "agent-endpoint.pfx");

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
            Certificate = OperatingSystem.IsWindows() ? FromMachineStore(log) : FromFile(log);
            return Certificate;
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException or IOException)
        {
            log.Warning(ex, "Could not set up the agent endpoint certificate; agents cannot connect. Run as the service (LocalSystem) or elevated.");
            return null;
        }
    }

    private static X509Certificate2 FromMachineStore(Serilog.ILogger log)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        var existing = store.Certificates
            .Find(X509FindType.FindBySubjectDistinguishedName, Subject, validOnly: false)
            .Where(c => c.HasPrivateKey && c.NotAfter > DateTime.Now.AddDays(30))
            .OrderByDescending(c => c.NotAfter)
            .FirstOrDefault();
        if (existing != null) return existing;

        // Re-import so the private key is persisted in the machine key store (Kestrel needs that)
        using var created = Create();
        var cert = X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pfx), null,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
        store.Add(cert);
        log.Information("Created the agent endpoint certificate (SHA-256 {Fingerprint}).", AgentSecrets.Fingerprint(cert));
        return cert;
    }

    private static X509Certificate2 FromFile(Serilog.ILogger log)
    {
        if (File.Exists(PfxFile))
        {
            var existing = X509CertificateLoader.LoadPkcs12FromFile(PfxFile, null);
            if (existing.NotAfter > DateTime.Now.AddDays(30)) return existing;
        }
        using var created = Create();
        SecretStore.WriteProtected(PfxFile, created.Export(X509ContentType.Pfx));
        var cert = X509CertificateLoader.LoadPkcs12FromFile(PfxFile, null);
        log.Information("Created the agent endpoint certificate (SHA-256 {Fingerprint}).", AgentSecrets.Fingerprint(cert));
        return cert;
    }

    private static X509Certificate2 Create()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(Subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1")], critical: false)); // server authentication
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(Environment.MachineName);
        request.CertificateExtensions.Add(san.Build());
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(20));
    }
}
