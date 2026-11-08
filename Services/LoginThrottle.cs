using System.Net;

namespace FileAccessMonitor.Services;

// Limits failed sign-ins without letting one person lock a user out for everyone: failures count per
// user name and client address, so wrong passwords from one address stop that address only. An address
// that fails for many names, and a name that fails from many addresses, are stopped too. Kept in memory:
// a restart of the service starts the counts again.
public class LoginThrottle(Func<DateTime>? clock = null)
{
    internal static readonly TimeSpan Window = TimeSpan.FromMinutes(15);
    internal const int PerUserAndAddress = 5;
    internal const int PerAddress = 20;
    internal const int PerUser = 100;
    private const int MaxKeys = 50_000;

    private readonly Func<DateTime> _now = clock ?? (() => DateTime.UtcNow);
    private readonly object _lock = new();
    private readonly Dictionary<string, Queue<DateTime>> _failures = new();

    public bool IsBlocked(string user, IPAddress? address)
    {
        var now = _now();
        lock (_lock)
        {
            return Count(PairKey(user, address), now) >= PerUserAndAddress
                || (AddressKey(address) is { } a && Count(a, now) >= PerAddress)
                || Count(UserKey(user), now) >= PerUser;
        }
    }

    public void Failed(string user, IPAddress? address)
    {
        var now = _now();
        lock (_lock)
        {
            if (_failures.Count > MaxKeys) Prune(now);
            Add(PairKey(user, address), now, PerUserAndAddress);
            if (AddressKey(address) is { } a) Add(a, now, PerAddress);
            Add(UserKey(user), now, PerUser);
        }
    }

    // A correct password from this address ends the wait for this name here (not for other addresses)
    public void Succeeded(string user, IPAddress? address)
    {
        lock (_lock) _failures.Remove(PairKey(user, address));
    }

    private static string Name(string user) => (user ?? "").Trim().ToUpperInvariant();
    private static string PairKey(string user, IPAddress? address) => $"p:{Name(user)}|{address}";
    private static string UserKey(string user) => $"u:{Name(user)}";
    // A reverse proxy on this machine (not listed in ReverseProxy:KnownProxies) makes every sign-in come from
    // loopback: counting them together would let anyone stop everyone's sign-in, so loopback is not counted
    private static string? AddressKey(IPAddress? address) =>
        address == null || IPAddress.IsLoopback(address) ? null : $"a:{address}";

    private void Add(string key, DateTime now, int keep)
    {
        if (!_failures.TryGetValue(key, out var times)) _failures[key] = times = new Queue<DateTime>();
        times.Enqueue(now);
        while (times.Count > keep) times.Dequeue();
    }

    private int Count(string key, DateTime now)
    {
        if (!_failures.TryGetValue(key, out var times)) return 0;
        while (times.Count > 0 && now - times.Peek() >= Window) times.Dequeue();
        if (times.Count == 0) _failures.Remove(key);
        return times.Count;
    }

    private void Prune(DateTime now)
    {
        foreach (var key in _failures.Keys.ToList()) Count(key, now);
        // Still too many (failures from very many addresses): forget the oldest names and addresses
        if (_failures.Count > MaxKeys)
            foreach (var key in _failures.OrderBy(e => e.Value.Last()).Take(_failures.Count - MaxKeys / 2).Select(e => e.Key).ToList())
                _failures.Remove(key);
    }
}
