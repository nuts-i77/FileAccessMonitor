using System.Net;
using System.Net.Sockets;
using FileAccessMonitor.Controllers;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

// 1.11: the webhook cannot be pointed at this machine, link-local addresses (cloud metadata) and the like
public class WebhookGuardTests
{
    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.255.255.254", true)]
    [InlineData("::1", true)]
    [InlineData("169.254.169.254", true)]       // cloud metadata
    [InlineData("169.254.0.1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("febf::1", true)]               // the end of fe80::/10
    [InlineData("0.0.0.0", true)]
    [InlineData("::", true)]
    [InlineData("224.0.0.251", true)]
    [InlineData("239.255.255.250", true)]
    [InlineData("ff02::1", true)]
    [InlineData("255.255.255.255", true)]
    [InlineData("::ffff:127.0.0.1", true)]      // IPv4 inside IPv6
    [InlineData("::ffff:169.254.169.254", true)]
    [InlineData("::127.0.0.1", true)]
    [InlineData("64:ff9b::169.254.169.254", true)]
    [InlineData("10.1.2.3", false)]             // private ranges stay allowed
    [InlineData("172.16.0.1", false)]
    [InlineData("172.31.255.255", false)]
    [InlineData("192.168.0.253", false)]
    [InlineData("::ffff:192.168.0.253", false)]
    [InlineData("8.8.8.8", false)]
    [InlineData("169.253.1.1", false)]
    [InlineData("fc00::1", false)]
    [InlineData("2001:db8::1", false)]
    [InlineData("fec0::1", false)]
    public void Addresses_are_classified(string address, bool refused) =>
        Assert.Equal(refused, WebhookGuard.IsRefused(IPAddress.Parse(address)));

    [Theory]
    [InlineData("https://hooks.slack.com/services/T000/B000/XXXX", WebhookUrlProblem.None)]
    [InlineData("https://example.webhook.office.com/webhookb2/abc", WebhookUrlProblem.None)]
    [InlineData("http://192.168.0.20:8065/hooks/abc", WebhookUrlProblem.None)]
    [InlineData("http://chat.corp.example/hooks/abc", WebhookUrlProblem.None)]
    [InlineData("http://127.0.0.1:8080/", WebhookUrlProblem.Forbidden)]
    [InlineData("http://127.1/", WebhookUrlProblem.Forbidden)]
    [InlineData("http://2130706433/", WebhookUrlProblem.Forbidden)]                 // 127.0.0.1 as one number
    [InlineData("http://[::1]:8080/", WebhookUrlProblem.Forbidden)]
    [InlineData("http://localhost/hook", WebhookUrlProblem.Forbidden)]
    [InlineData("http://LOCALHOST./hook", WebhookUrlProblem.Forbidden)]
    [InlineData("http://api.localhost/hook", WebhookUrlProblem.Forbidden)]
    [InlineData("http://169.254.169.254/latest/meta-data/", WebhookUrlProblem.Forbidden)]
    [InlineData("http://[fe80::1%25eth0]/", WebhookUrlProblem.Forbidden)]
    [InlineData("http://0.0.0.0/", WebhookUrlProblem.Forbidden)]
    [InlineData("http://[::]/", WebhookUrlProblem.Forbidden)]
    [InlineData("http://224.0.0.1/", WebhookUrlProblem.Forbidden)]
    [InlineData("http://[::ffff:127.0.0.1]/", WebhookUrlProblem.Forbidden)]
    [InlineData("ftp://hooks.example.com/x", WebhookUrlProblem.Scheme)]
    [InlineData("file:///etc/passwd", WebhookUrlProblem.Scheme)]
    [InlineData("gopher://example.com/", WebhookUrlProblem.Scheme)]
    [InlineData("hooks.example.com/x", WebhookUrlProblem.Invalid)]
    [InlineData("not a url", WebhookUrlProblem.Invalid)]
    [InlineData("", WebhookUrlProblem.Invalid)]
    public void Urls_are_checked(string url, WebhookUrlProblem expected) =>
        Assert.Equal(expected, WebhookGuard.Check(url));

    [Fact]
    public async Task A_name_that_resolves_to_refused_addresses_only_is_refused_when_saved()
    {
        static Func<string, CancellationToken, Task<IPAddress[]>> Resolves(params string[] ips) =>
            (_, _) => Task.FromResult(ips.Select(IPAddress.Parse).ToArray());

        Assert.Equal(WebhookUrlProblem.Forbidden, await WebhookGuard.CheckAsync("https://rebind.example/x", default, Resolves("169.254.169.254")));
        Assert.Equal(WebhookUrlProblem.None, await WebhookGuard.CheckAsync("https://chat.example/x", default, Resolves("10.0.0.5")));
        Assert.Equal(WebhookUrlProblem.None, await WebhookGuard.CheckAsync("https://mixed.example/x", default, Resolves("127.0.0.1", "10.0.0.5"))); // the connection skips the refused one
        Assert.Equal(WebhookUrlProblem.None, await WebhookGuard.CheckAsync("https://down.example/x", default,
            (_, _) => throw new SocketException((int)SocketError.HostNotFound)));                                                                    // not resolvable from here: not this check's business
        Assert.Equal(WebhookUrlProblem.Forbidden, await WebhookGuard.CheckAsync("http://127.0.0.1/x"));
    }

    [Fact]
    public async Task The_connection_is_refused_when_the_name_resolves_to_a_refused_address()
    {
        // The name looks harmless; the answer of the DNS is not (DNS rebinding)
        Task<IPAddress[]> Rebinds(string _, CancellationToken __) => Task.FromResult(new[] { IPAddress.Parse("169.254.169.254") });
        await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await WebhookGuard.ConnectAsync(new DnsEndPoint("hooks.example.com", 80), Rebinds, default));
        await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await WebhookGuard.ConnectAsync(new DnsEndPoint("127.0.0.1", 80), null, default));
    }

    [Fact]
    public async Task The_shared_client_never_connects_to_loopback()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        await Assert.ThrowsAsync<HttpRequestException>(() => WebhookGuard.Client.PostAsync($"http://127.0.0.1:{port}/hook", new StringContent("{}")));
        await Assert.ThrowsAsync<HttpRequestException>(() => WebhookGuard.Client.PostAsync($"http://localhost:{port}/hook", new StringContent("{}")));
        Assert.False(listener.Pending());   // nothing reached the listener
    }

    // ---- save validation

    private static AlertSettingsRequest Request(string? webhookUrl) =>
        new(true, 100, 100, 5, 30, "en", "slack", webhookUrl, null, 25, false, null, null, null, null);

    [Theory]
    [InlineData("http://127.0.0.1:9/hook")]
    [InlineData("http://169.254.169.254/latest/meta-data")]
    [InlineData("http://localhost/hook")]
    [InlineData("ftp://example.com/hook")]
    [InlineData("nonsense")]
    public async Task Saving_a_forbidden_webhook_gives_a_clear_error(string url)
    {
        var error = await AlertsController.ValidateWebhookAsync(Request(url));
        Assert.NotNull(error);
        Assert.Contains("webhook", error, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(null)]                                   // keep the stored one
    [InlineData("")]                                     // clear it
    [InlineData("   ")]
    [InlineData("http://192.168.0.20:8065/hooks/abc")]   // an internal chat server
    [InlineData("https://10.1.2.3/hooks/abc")]
    public async Task Saving_an_allowed_webhook_passes(string? url) =>
        Assert.Null(await AlertsController.ValidateWebhookAsync(Request(url)));
}
