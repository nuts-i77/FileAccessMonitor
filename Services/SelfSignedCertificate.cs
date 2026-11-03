using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FileAccessMonitor.Services;

// Self-signed server certificates kept by the machine: in the machine certificate store on Windows
// (the private key must be persisted in the machine key store for Kestrel), as a PFX file in the
// data folder on Linux (readable by the service account only). Shared by the agent endpoint and
// the web GUI.
public static class SelfSignedCertificate
{
    // Returns a stored certificate with this subject that isUsable accepts (the newest one), or
    // creates one. replaceStale: certificates with the subject that are not usable are removed
    // when a new one is made (the web certificate is renewed when the machine's names change; the
    // agent certificate is never touched, agents pin its fingerprint).
    public static X509Certificate2 LoadOrCreate(string subject, string pfxFileName, IReadOnlyCollection<string> sanNames,
        int validityYears, Func<X509Certificate2, bool> isUsable, Serilog.ILogger log, string description,
        bool replaceStale = false)
    {
        return OperatingSystem.IsWindows()
            ? FromMachineStore(subject, sanNames, validityYears, isUsable, log, description, replaceStale)
            : FromFile(Path.Combine(AppPaths.DataDir, pfxFileName), subject, sanNames, validityYears, isUsable, log, description);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static X509Certificate2 FromMachineStore(string subject, IReadOnlyCollection<string> sanNames, int validityYears,
        Func<X509Certificate2, bool> isUsable, Serilog.ILogger log, string description, bool replaceStale)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        var all = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, subject, validOnly: false);
        var existing = all.Where(isUsable).OrderByDescending(c => c.NotAfter).FirstOrDefault();
        if (existing != null) return existing;

        // Re-import so the private key is persisted in the machine key store (Kestrel needs that)
        using var created = Create(subject, sanNames, validityYears);
        var cert = X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pfx), null,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
        store.Add(cert);
        if (replaceStale)
            foreach (var old in all) store.Remove(old);
        log.Information("Created the {Description} certificate (SHA-256 {Fingerprint}).", description, AgentSecrets.Fingerprint(cert));
        return cert;
    }

    private static X509Certificate2 FromFile(string pfxFile, string subject, IReadOnlyCollection<string> sanNames, int validityYears,
        Func<X509Certificate2, bool> isUsable, Serilog.ILogger log, string description)
    {
        if (File.Exists(pfxFile))
        {
            var existing = X509CertificateLoader.LoadPkcs12FromFile(pfxFile, null);
            if (isUsable(existing)) return existing;
        }
        using var created = Create(subject, sanNames, validityYears);
        SecretStore.WriteProtected(pfxFile, created.Export(X509ContentType.Pfx));
        var cert = X509CertificateLoader.LoadPkcs12FromFile(pfxFile, null);
        log.Information("Created the {Description} certificate (SHA-256 {Fingerprint}).", description, AgentSecrets.Fingerprint(cert));
        return cert;
    }

    // RSA 2048 / SHA-256, server authentication; sanNames are DNS names or IP addresses
    public static X509Certificate2 Create(string subject, IReadOnlyCollection<string> sanNames, int validityYears)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1")], critical: false)); // server authentication
        var san = new SubjectAlternativeNameBuilder();
        foreach (var name in sanNames)
        {
            if (IPAddress.TryParse(name, out var ip)) san.AddIpAddress(ip);
            else san.AddDnsName(name);
        }
        request.CertificateExtensions.Add(san.Build());
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(validityYears));
    }

    // DNS names and IP addresses in the certificate's subject alternative name extension
    public static IReadOnlyList<string> Names(X509Certificate2 cert)
    {
        var names = new List<string>();
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value != "2.5.29.17") continue;
            var san = new X509SubjectAlternativeNameExtension(ext.RawData, ext.Critical);
            names.AddRange(san.EnumerateDnsNames());
            names.AddRange(san.EnumerateIPAddresses().Select(ip => ip.ToString()));
        }
        return names;
    }
}
