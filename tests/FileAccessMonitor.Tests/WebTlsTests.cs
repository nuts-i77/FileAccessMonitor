using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.DataProtection;

namespace FileAccessMonitor.Tests;

public class WebTlsTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "fam-webtls-" + Guid.NewGuid().ToString("N"));

    public WebTlsTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void Names_cover_the_machine_its_addresses_and_loopback()
    {
        var names = WebTls.BuildNames("NAS01", "nas01.corp.example.", [
            IPAddress.Parse("192.168.0.10"), IPAddress.Parse("fe80::1%3"), IPAddress.Parse("2001:db8::5"),
            IPAddress.Loopback, IPAddress.Any, IPAddress.Parse("192.168.0.10")]);
        Assert.Equal(["NAS01", "nas01.corp.example", "localhost", "192.168.0.10", "2001:db8::5", "127.0.0.1", "::1"], names);
    }

    [Fact]
    public void Names_without_a_domain_name_are_still_complete() =>
        Assert.Equal(["nas01", "localhost", "10.0.0.5", "127.0.0.1", "::1"], WebTls.BuildNames("nas01", null, [IPAddress.Parse("10.0.0.5")]));

    [Fact]
    public void The_machine_s_current_names_include_the_machine_name_and_localhost()
    {
        var names = WebTls.CurrentNames();
        Assert.Contains(Environment.MachineName, names);
        Assert.Contains("localhost", names);
        Assert.Contains("127.0.0.1", names);
    }

    [Theory]
    [InlineData("a,b,localhost", "a,b", false)]
    [InlineData("a,b", "a,b,10.0.0.9", true)]    // a new address
    [InlineData("A,LOCALHOST", "a,localhost", false)]
    [InlineData("old", "new", true)]             // renamed machine
    public void The_certificate_is_made_again_when_a_name_or_address_is_missing(string have, string wanted, bool renew) =>
        Assert.Equal(renew, WebTls.NeedsNewCertificate(have.Split(','), wanted.Split(',')));

    [Fact]
    public void A_stored_certificate_is_kept_while_it_covers_the_current_names()
    {
        using var cert = SelfSignedCertificate.Create(WebTls.Subject, ["NAS01", "localhost", "10.0.0.5"], 10);
        Assert.True(WebTls.IsUsable(cert, ["NAS01", "localhost"]));
        Assert.True(WebTls.IsUsable(cert, ["nas01", "10.0.0.5"]));
        Assert.False(WebTls.IsUsable(cert, ["NAS01", "10.0.0.6"]));   // address changed
        Assert.False(WebTls.IsUsable(cert, ["NAS02"]));               // renamed

        using var expiring = SelfSignedCertificate.Create(WebTls.Subject, ["NAS01"], 0);
        Assert.False(WebTls.IsUsable(expiring, ["NAS01"]));
    }

    [Theory]
    [InlineData("http://0.0.0.0:8080", "https://0.0.0.0:8080")]
    [InlineData("HTTP://*:8443", "https://*:8443")]
    [InlineData("http://0.0.0.0:8080;http://[::]:8081", "https://0.0.0.0:8080;https://[::]:8081")]
    [InlineData("https://0.0.0.0:8080", "https://0.0.0.0:8080")]
    public void The_url_scheme_is_replaced(string url, string expected) =>
        Assert.Equal(expected, WebTls.ToHttps(url));

    [Theory]
    [InlineData("http://0.0.0.0:8080", 8080)]
    [InlineData("http://*:9000", 9000)]
    [InlineData("http://+:7000;http://0.0.0.0:7001", 7000)]
    public void The_web_port_is_read_from_the_url(string url, int port) =>
        Assert.Equal(port, WebTls.PortOf(url));

    [Fact]
    public void Settings_are_read_from_settings_json()
    {
        var off = WebTlsSettings.Parse(new JsonObject());
        Assert.Equal((false, "SelfSigned", 0), (off.Enabled, off.Mode, off.RedirectPort));

        var on = WebTlsSettings.Parse(JsonNode.Parse("""{"Web":{"Https":{"Enabled":true}}}""")!.AsObject());
        Assert.Equal((true, "SelfSigned", "web-user.pfx", 0), (on.Enabled, on.Mode, on.PfxFile, on.RedirectPort));

        var pfx = WebTlsSettings.Parse(JsonNode.Parse(
            """{"Web":{"Https":{"Enabled":true,"Mode":"pfx","PfxFile":"my.pfx","PfxPassword":"enc:x","RedirectPort":8081}}}""")!.AsObject());
        Assert.Equal((true, "Pfx", "my.pfx", "enc:x", 8081), (pfx.Enabled, pfx.Mode, pfx.PfxFile, pfx.PfxPassword, pfx.RedirectPort));
        Assert.True(pfx.UsesPfx);

        // nonsense falls back to the defaults
        var bad = WebTlsSettings.Parse(JsonNode.Parse("""{"Web":{"Https":{"Enabled":true,"Mode":"Foo","RedirectPort":70000}}}""")!.AsObject());
        Assert.Equal(("SelfSigned", 0), (bad.Mode, bad.RedirectPort));
    }

    [Fact]
    public void The_pfx_password_is_protected_with_data_protection()
    {
        var provider = new EphemeralDataProtectionProvider();
        var stored = WebTls.ProtectPassword("s3cret!", provider)!;
        Assert.StartsWith("enc:", stored);
        Assert.DoesNotContain("s3cret", stored);
        Assert.Equal("s3cret!", WebTls.UnprotectPassword(stored, provider));
        Assert.Equal("plain", WebTls.UnprotectPassword("plain", provider)); // a hand-written password still works
        Assert.Null(WebTls.ProtectPassword("", provider));
        Assert.Null(WebTls.UnprotectPassword(null, provider));
    }

    private static byte[] Pfx(string? password, int years = 1, bool withKey = true)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=nas01.corp.example", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("nas01.corp.example");
        request.CertificateExtensions.Add(san.Build());
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-400), DateTimeOffset.UtcNow.AddYears(years));
        return withKey ? cert.Export(X509ContentType.Pfx, password) : cert.Export(X509ContentType.Pfx);
    }

    [Fact]
    public void A_valid_pfx_is_accepted()
    {
        using var cert = WebTls.ReadPfx(Pfx("pw"), "pw");
        Assert.True(cert.HasPrivateKey);
        Assert.Contains("nas01.corp.example", WebTls.Describe(cert));
        Assert.Contains(AgentSecrets.Fingerprint(cert), WebTls.Describe(cert));
    }

    [Fact]
    public void A_pfx_with_the_wrong_password_an_expired_certificate_or_garbage_is_refused()
    {
        Assert.Throws<InvalidOperationException>(() => WebTls.ReadPfx(Pfx("pw"), "other"));
        Assert.Contains("expired", Assert.Throws<InvalidOperationException>(() => WebTls.ReadPfx(Pfx("pw", years: -1), "pw")).Message);
        Assert.Throws<InvalidOperationException>(() => WebTls.ReadPfx([1, 2, 3, 4], null));
    }

    [Fact]
    public void A_certificate_without_a_private_key_is_refused()
    {
        using var rsa = RSA.Create(2048);
        using var withKey = new CertificateRequest("CN=x", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var publicOnly = withKey.Export(X509ContentType.Cert);
        Assert.Throws<InvalidOperationException>(() => WebTls.ReadPfx(publicOnly, null));
    }

    [Fact]
    public void Wildcard_and_exact_names_match_the_machine()
    {
        Assert.True(WebTls.MatchesName("nas01.corp.example", "NAS01.corp.example"));
        Assert.True(WebTls.MatchesName("*.corp.example", "nas01.corp.example"));
        Assert.False(WebTls.MatchesName("*.corp.example", "nas01"));
        Assert.False(WebTls.MatchesName("other.example", "nas01.corp.example"));
        Assert.False(WebTls.MatchesName(null, "nas01"));
    }

    [Fact]
    public void The_command_switches_https_on_and_off_in_settings_json()
    {
        var file = Path.Combine(_dir, "settings.json");
        File.WriteAllText(file, """{ "LocalCollection": false }""");
        string Run(params string[] args)
        {
            var output = new StringWriter();
            var code = WebTls.RunCommand(["web-https", .. args], output, output, new EphemeralDataProtectionProvider(), file);
            return code + "|" + output.ToString().Trim();
        }

        Assert.StartsWith("0|off", Run("status"));
        Assert.StartsWith("0|HTTPS for the web GUI: on", Run("on", "--redirect-port", "8081"));
        Assert.Equal("0|on\nmode: SelfSigned\nredirect port: 8081", Run("status").Replace("\r\n", "\n"));
        Assert.StartsWith("0|HTTPS for the web GUI: off", Run("off"));
        Assert.StartsWith("0|off", Run("status"));

        var settings = JsonNode.Parse(File.ReadAllText(file))!;
        Assert.False((bool)settings["LocalCollection"]!);       // other settings stay
        Assert.False((bool)settings["Web"]!["Https"]!["Enabled"]!);
        Assert.Equal(8081, (int)settings["Web"]!["Https"]!["RedirectPort"]!);

        Assert.StartsWith("2|Usage", Run("sideways"));
        Assert.StartsWith("2|", Run("on", "--redirect-port", "99999"));
        Assert.StartsWith("1|", Run("on", "--pfx", Path.Combine(_dir, "missing.pfx")));
        Assert.StartsWith("0|off", Run("status")); // a failed "on" changes nothing
    }

    [Fact]
    public void The_command_refuses_a_bad_pfx_without_changing_settings()
    {
        var file = Path.Combine(_dir, "settings.json");
        var pfx = Path.Combine(_dir, "web.pfx");
        File.WriteAllBytes(pfx, Pfx("pw"));
        var output = new StringWriter();
        var code = WebTls.RunCommand(["web-https", "on", "--pfx", pfx, "--pfx-password", "wrong"], output, output,
            new EphemeralDataProtectionProvider(), file);
        Assert.Equal(1, code);
        Assert.Contains("password", output.ToString());
        Assert.False(File.Exists(file));
    }

    [Theory]
    [InlineData("http://0.0.0.0:8080", "http://localhost:8080")]
    [InlineData("http://*:9090", "http://localhost:9090")]
    [InlineData("http://192.168.0.5:8080;http://0.0.0.0:8080", "http://localhost:8080")]
    [InlineData("http://[::]:8081;http://+:8082", "http://localhost:8081;http://localhost:8082")]
    public void Without_a_certificate_the_web_gui_listens_on_loopback_only(string url, string expected) =>
        Assert.Equal(expected, WebTls.ToLoopback(url));

    [Fact]
    public void A_certificate_that_cannot_be_loaded_is_reported_as_a_loopback_only_problem()
    {
        var log = new Serilog.LoggerConfiguration().CreateLogger();
        // The PFX file named in the settings does not exist in the data folder
        var settings = new WebTlsSettings(true, WebTlsSettings.PfxMode, "missing-" + Guid.NewGuid().ToString("N") + ".pfx", null, 8081);
        Assert.Null(WebTls.Initialize(settings, log, new EphemeralDataProtectionProvider()));
        Assert.False(WebTls.Status.Https);
        Assert.True(WebTls.Status.LoopbackOnly);
        Assert.False(string.IsNullOrEmpty(WebTls.Status.Problem));

        Assert.Null(WebTls.Initialize(settings with { Enabled = false }, log));
        Assert.False(WebTls.Status.LoopbackOnly); // off is not an error
    }
}
