using System.Net;
using System.Net.Sockets;

namespace FileAccessMonitor.Services;

public enum WebhookUrlProblem { None, Invalid, Scheme, Forbidden }

// Where the notification webhook may send to. A webhook URL is typed in by an Admin, but this server
// connects to it from inside the network, so it must not be a way to reach the server itself or the
// cloud metadata service (169.254.169.254). Refused: loopback, link-local, unspecified and multicast
// addresses. Private ranges (10/8, 172.16/12, 192.168/16) stay allowed: internal chat servers.
//
// The address is checked where the connection is made (ConnectAsync), not only in the URL, so a name
// that resolves to a refused address (or changes to one later, "DNS rebinding") does not get through.
// Redirects are not followed, so a destination cannot send this server on to a refused address.
public static class WebhookGuard
{
    public static bool IsRefused(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            // 0.0.0.0/8 (unspecified), 127.0.0.0/8 (loopback), 169.254.0.0/16 (link-local), 224.0.0.0/4 (multicast)
            // and the reserved block above it, which includes the broadcast address
            return b[0] is 0 or 127 || (b[0] == 169 && b[1] == 254) || b[0] >= 224;
        }
        if (address.AddressFamily != AddressFamily.InterNetworkV6) return true;

        if (address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.IPv6Loopback)) return true;
        if (address.IsIPv6LinkLocal || address.IsIPv6Multicast) return true;
        // An IPv4 address inside an IPv6 one: IPv4-compatible (::a.b.c.d) and NAT64 (64:ff9b::a.b.c.d)
        var v6 = address.GetAddressBytes();
        var compatible = v6.Take(12).All(x => x == 0);
        var nat64 = v6[0] == 0x00 && v6[1] == 0x64 && v6[2] == 0xff && v6[3] == 0x9b && v6.Skip(4).Take(8).All(x => x == 0);
        return (compatible || nat64) && IsRefused(new IPAddress(v6[12..]));
    }

    // The URL as typed: http or https, and not an address (or "localhost") that is refused.
    // A name that merely resolves to a refused address is stopped when the connection is made.
    public static WebhookUrlProblem Check(string? url)
    {
        if (!Uri.TryCreate(url?.Trim(), UriKind.Absolute, out var uri)) return WebhookUrlProblem.Invalid;
        if (uri.Scheme is not ("http" or "https")) return WebhookUrlProblem.Scheme;
        if (string.IsNullOrEmpty(uri.Host)) return WebhookUrlProblem.Invalid;
        if (uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6)
        {
            var text = uri.Host.Trim('[', ']');
            var zone = text.IndexOf('%');
            return IPAddress.TryParse(zone < 0 ? text : text[..zone], out var ip) && IsRefused(ip)
                ? WebhookUrlProblem.Forbidden : WebhookUrlProblem.None;
        }
        var host = uri.IdnHost.TrimEnd('.');
        return host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)
            ? WebhookUrlProblem.Forbidden : WebhookUrlProblem.None;
    }

    // Check, and also resolve the name: whether it leads only to refused addresses. A name that does not
    // resolve passes here (the server may not be reachable from here at all); sending fails then.
    public static async Task<WebhookUrlProblem> CheckAsync(string? url, CancellationToken ct = default,
        Func<string, CancellationToken, Task<IPAddress[]>>? resolve = null)
    {
        var problem = Check(url);
        if (problem != WebhookUrlProblem.None) return problem;
        var uri = new Uri(url!.Trim());
        if (uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6) return problem;
        try
        {
            var addresses = await (resolve ?? Dns.GetHostAddressesAsync)(uri.IdnHost, ct);
            return addresses.Length > 0 && addresses.All(IsRefused) ? WebhookUrlProblem.Forbidden : WebhookUrlProblem.None;
        }
        catch (SocketException)
        {
            return WebhookUrlProblem.None;
        }
    }

    // For SocketsHttpHandler.ConnectCallback: resolves the host and connects to an address that is not
    // refused (a name with several addresses may have refused ones among them: those are skipped).
    public static ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken ct) =>
        ConnectAsync(context.DnsEndPoint, null, ct);

    internal static async ValueTask<Stream> ConnectAsync(DnsEndPoint endPoint, Func<string, CancellationToken, Task<IPAddress[]>>? resolve,
        CancellationToken ct)
    {
        var addresses = IPAddress.TryParse(endPoint.Host, out var literal)
            ? [literal]
            : await (resolve ?? Dns.GetHostAddressesAsync)(endPoint.Host, ct);
        var allowed = addresses.Where(a => !IsRefused(a)).ToArray();
        if (allowed.Length == 0)
            throw new HttpRequestException($"The webhook destination {endPoint.Host} is a loopback, link-local, unspecified or multicast address, which is not allowed.");

        SocketException? last = null;
        foreach (var address in allowed)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(address, endPoint.Port), ct);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (SocketException ex)
            {
                socket.Dispose();
                last = ex;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }
        throw new HttpRequestException($"Could not connect to the webhook destination {endPoint.Host}.", last);
    }

    // One client for all webhooks: the connection check above, no redirects, no proxy
    public static readonly HttpClient Client = new(new SocketsHttpHandler
    {
        ConnectCallback = ConnectAsync,
        AllowAutoRedirect = false,
        UseProxy = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
    })
    {
        Timeout = TimeSpan.FromSeconds(15),
    };
}
