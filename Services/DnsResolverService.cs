using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace FileAccessMonitor.Services;

public class DnsResolverService(ILogger<DnsResolverService> logger)
{
    private volatile string? _dnsServer;
    private readonly ConcurrentDictionary<string, (string Name, DateTime Expiry)> _cache = new();

    public void SetDnsServer(string? server) =>
        _dnsServer = string.IsNullOrWhiteSpace(server) ? null : server.Trim();

    public string? GetDnsServer() => _dnsServer;

    public string? TryResolve(string? ip)
    {
        if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(_dnsServer))
            return null;

        if (_cache.TryGetValue(ip, out var cached) && cached.Expiry > DateTime.UtcNow)
            return string.IsNullOrEmpty(cached.Name) ? null : cached.Name;

        try
        {
            var hostname = PtrLookup(ip, _dnsServer);
            _cache[ip] = (hostname ?? "", DateTime.UtcNow.AddHours(1));
            return hostname;
        }
        catch (Exception ex)
        {
            logger.LogDebug("DNS PTR lookup failed for {Ip}: {Msg}", ip, ex.Message);
            _cache[ip] = ("", DateTime.UtcNow.AddMinutes(5));
            return null;
        }
    }

    private static string? PtrLookup(string ip, string dnsServer)
    {
        var parts = ip.Split('.');
        if (parts.Length != 4) return null;
        var ptrName = $"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa";

        ushort txId = (ushort)Random.Shared.Next(1, 0xFFFF);
        var query = BuildQuery(txId, ptrName);

        using var udp = new UdpClient();
        udp.Client.SendTimeout = 1500;
        udp.Client.ReceiveTimeout = 1500;
        udp.Connect(dnsServer, 53);
        udp.Send(query);
        var remote = new IPEndPoint(IPAddress.Any, 0);
        var resp = udp.Receive(ref remote);

        if (resp.Length < 12) return null;
        if ((ushort)((resp[0] << 8) | resp[1]) != txId) return null;
        int ancount = (resp[6] << 8) | resp[7];
        if (ancount == 0) return null;

        int pos = 12;
        SkipName(resp, ref pos);
        pos += 4; // QTYPE + QCLASS

        SkipName(resp, ref pos);
        if (pos + 10 > resp.Length) return null;
        int type = (resp[pos] << 8) | resp[pos + 1]; pos += 8; // type(2)+class(2)+TTL(4)
        pos += 2; // RDLENGTH

        if (type != 12) return null; // not PTR
        return ReadName(resp, ref pos);
    }

    private static void SkipName(byte[] data, ref int pos)
    {
        while (pos < data.Length)
        {
            if ((data[pos] & 0xC0) == 0xC0) { pos += 2; return; }
            int len = data[pos++];
            if (len == 0) return;
            pos += len;
        }
    }

    private static string? ReadName(byte[] data, ref int pos)
    {
        var parts = new List<string>();
        int cur = pos;
        bool jumped = false;
        int afterJump = pos;
        int limit = 20;
        while (cur < data.Length && limit-- > 0)
        {
            if ((data[cur] & 0xC0) == 0xC0)
            {
                if (!jumped) afterJump = cur + 2;
                cur = ((data[cur] & 0x3F) << 8) | data[cur + 1];
                jumped = true;
            }
            else
            {
                int len = data[cur++];
                if (len == 0) break;
                if (cur + len > data.Length) break;
                parts.Add(Encoding.ASCII.GetString(data, cur, len));
                cur += len;
            }
        }
        pos = jumped ? afterJump : cur;
        return parts.Count > 0 ? string.Join('.', parts) : null;
    }

    private static byte[] BuildQuery(ushort txId, string name)
    {
        var ms = new MemoryStream();
        ms.WriteByte((byte)(txId >> 8)); ms.WriteByte((byte)txId);
        ms.WriteByte(0x01); ms.WriteByte(0x00); // RD=1
        ms.WriteByte(0); ms.WriteByte(1);        // QDCOUNT=1
        ms.WriteByte(0); ms.WriteByte(0);
        ms.WriteByte(0); ms.WriteByte(0);
        ms.WriteByte(0); ms.WriteByte(0);
        foreach (var label in name.Split('.'))
        {
            ms.WriteByte((byte)label.Length);
            foreach (var c in label) ms.WriteByte((byte)c);
        }
        ms.WriteByte(0);
        ms.WriteByte(0); ms.WriteByte(12); // QTYPE=PTR
        ms.WriteByte(0); ms.WriteByte(1);  // QCLASS=IN
        return ms.ToArray();
    }
}
