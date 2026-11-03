using System.Security.Cryptography.X509Certificates;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class SelfSignedCertificateTests
{
    [Fact]
    public void A_certificate_covers_the_names_and_addresses_given()
    {
        using var cert = SelfSignedCertificate.Create("CN=Test Web", ["NAS01", "nas01.corp.example", "localhost", "192.168.0.10", "::1"], 10);
        Assert.Equal("CN=Test Web", cert.Subject);
        Assert.True(cert.HasPrivateKey);
        Assert.Equal(
            new[] { "NAS01", "nas01.corp.example", "localhost", "192.168.0.10", "::1" }.Order(StringComparer.OrdinalIgnoreCase),
            SelfSignedCertificate.Names(cert).Order(StringComparer.OrdinalIgnoreCase));
        Assert.InRange(cert.NotAfter, DateTime.Now.AddYears(10).AddDays(-3), DateTime.Now.AddYears(10).AddDays(3));
        var usage = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
        Assert.Contains(usage.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>(), o => o.Value == "1.3.6.1.5.5.7.3.1");
    }

    // Agents pin the agent endpoint certificate by fingerprint: how it is made must not change
    [Fact]
    public void The_agent_endpoint_certificate_is_made_as_before()
    {
        Assert.Equal("CN=FileAccessMonitor Agent Endpoint", AgentEndpoint.Subject);
        Assert.Equal("agent-endpoint.pfx", AgentEndpoint.PfxFileName);
        Assert.Equal(20, AgentEndpoint.ValidityYears);
        Assert.Equal([Environment.MachineName], AgentEndpoint.Names());

        using var cert = SelfSignedCertificate.Create(AgentEndpoint.Subject, AgentEndpoint.Names(), AgentEndpoint.ValidityYears);
        Assert.Equal(AgentEndpoint.Subject, cert.Subject);
        Assert.Equal([Environment.MachineName], SelfSignedCertificate.Names(cert));
        Assert.InRange(cert.NotAfter, DateTime.Now.AddYears(20).AddDays(-3), DateTime.Now.AddYears(20).AddDays(3));
        Assert.True(AgentEndpoint.IsUsable(cert));
    }

    [Fact]
    public void The_agent_certificate_is_replaced_only_when_it_is_close_to_expiry()
    {
        using var soon = SelfSignedCertificate.Create(AgentEndpoint.Subject, AgentEndpoint.Names(), 0);
        Assert.False(AgentEndpoint.IsUsable(soon));
    }
}
