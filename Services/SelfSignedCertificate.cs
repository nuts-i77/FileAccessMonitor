using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FileAccessMonitor.Services;

// Self-signed server certificates kept as a PFX file in the data folder (readable by the service
// account only). The web part runs as an unprivileged account (the virtual account
// NT SERVICE\FileAccessMonitor on Windows), which can neither add to the machine certificate store
// nor use a key that SYSTEM put in the machine key store; so the certificate is a file that the account
// itself can read and write. On Windows the file is loaded into the machine key set (not persisted, so
// nothing is left behind in the key store).
// Certificates that an earlier version (service as LocalSystem) put in the machine store stay in use as
// long as the account can use their key (the installer grants it read access to the key file), so the
// agent endpoint certificate, which agents pin by fingerprint, does not change on an upgrade.
// Shared by the agent endpoint and the web GUI.
public static class SelfSignedCertificate
{
    // Returns a stored certificate with this subject that isUsable accepts (the newest one), or
    // creates one. replaceStale: certificates with the subject that are not usable are replaced
    // (the web certificate is renewed when the machine's names change; the agent certificate is
    // never touched, agents pin its fingerprint).
    public static X509Certificate2 LoadOrCreate(string subject, string pfxFileName, IReadOnlyCollection<string> sanNames,
        int validityYears, Func<X509Certificate2, bool> isUsable, Serilog.ILogger log, string description,
        bool replaceStale = false)
    {
        var pfxFile = Path.Combine(AppPaths.DataDir, pfxFileName);
        if (OperatingSystem.IsWindows() && !File.Exists(pfxFile))
        {
            var legacy = FindInMachineStore(subject, isUsable);
            if (legacy != null && KeyIsUsable(legacy)) return legacy;
            // The agent certificate is pinned by the agents: never replace it behind their back
            if (legacy != null && !replaceStale)
                throw new CryptographicException(
                    "The agent endpoint certificate in the machine store cannot be used by this account (no access to its private key). " +
                    "Run the installer again; it gives the service account access to the key.");
        }
        return FromFile(pfxFile, subject, sanNames, validityYears, isUsable, log, description);
    }

    // The newest usable certificate with this subject in the machine store (null when there is none or
    // the store cannot be read)
    internal static X509Certificate2? FindInMachineStore(string subject, Func<X509Certificate2, bool> isUsable)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            return store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, subject, validOnly: false)
                .Where(isUsable).OrderByDescending(c => c.NotAfter).FirstOrDefault();
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    // Whether this account can sign with the certificate's private key (TLS needs that)
    internal static bool KeyIsUsable(X509Certificate2 cert)
    {
        try
        {
            using var rsa = cert.GetRSAPrivateKey();
            rsa?.SignData([1], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return rsa != null;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    // Windows needs a key set that SChannel (Kestrel) can use
    internal static X509KeyStorageFlags LoadFlags =>
        OperatingSystem.IsWindows() ? X509KeyStorageFlags.MachineKeySet : X509KeyStorageFlags.DefaultKeySet;

    private static X509Certificate2 FromFile(string pfxFile, string subject, IReadOnlyCollection<string> sanNames, int validityYears,
        Func<X509Certificate2, bool> isUsable, Serilog.ILogger log, string description)
    {
        if (File.Exists(pfxFile))
        {
            var existing = X509CertificateLoader.LoadPkcs12FromFile(pfxFile, null, LoadFlags);
            if (isUsable(existing)) return existing;
        }
        using var created = Create(subject, sanNames, validityYears);
        SecretStore.WriteProtected(pfxFile, created.Export(X509ContentType.Pfx));
        var cert = X509CertificateLoader.LoadPkcs12FromFile(pfxFile, null, LoadFlags);
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
