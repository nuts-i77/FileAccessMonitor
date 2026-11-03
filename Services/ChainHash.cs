using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using FileAccessMonitor.Models;

namespace FileAccessMonitor.Services;

// Tamper detection: the canonical form of a row and the HMAC that links it to the row before.
// hash = HMAC-SHA256(key, previousHash || canonical(row)); canonical = version byte 1, then every field
// as a 4-byte little-endian length plus UTF-8 bytes (null = length -1, numbers as invariant strings).
// Not thread safe: one instance per piece of work (it reuses its buffer).
public sealed class ChainHasher : IDisposable
{
    public const string Access = "access";
    public const string Audit = "audit";
    public static readonly string[] Chains = [Access, Audit];

    private const byte Version = 1;

    private readonly HMACSHA256 _hmac;
    private byte[] _buf = new byte[2048];
    private int _len;
    private int _canonicalStart;

    public ChainHasher(byte[] key) => _hmac = new HMACSHA256(key);

    public void Dispose() => _hmac.Dispose();

    // The canonical form of the row last hashed (for tests)
    public byte[] LastCanonical() => _buf.AsSpan(_canonicalStart, _len - _canonicalStart).ToArray();

    public byte[] Hash(ReadOnlySpan<byte> prev, long seq, AccessRecord r) =>
        AccessRow(prev, seq, r.ServerName, r.AccessTime.Ticks, r.AccessType, r.Denied, r.IsFolder, r.UserName,
            r.FilePath, r.FileName, r.FolderPath, r.ClientIp, r.ClientMachine, r.NewPath, r.Detail);

    public byte[] Hash(ReadOnlySpan<byte> prev, long seq, AuditLogEntry e) =>
        AuditRow(prev, seq, e.Time.Ticks, e.UserName, e.Action, e.Detail, e.ClientIp);

    public byte[] AccessRow(ReadOnlySpan<byte> prev, long seq, string server, long ticks, string type, bool denied,
        bool isFolder, string user, string filePath, string fileName, string folderPath, string? clientIp,
        string? clientMachine, string? newPath, string? detail)
    {
        Begin(prev);
        Text(Access); Num(seq); Text(server); Num(ticks); Text(type); Flag(denied); Flag(isFolder); Text(user);
        Text(filePath); Text(fileName); Text(folderPath); Text(clientIp); Text(clientMachine); Text(newPath); Text(detail);
        return Finish();
    }

    public byte[] AuditRow(ReadOnlySpan<byte> prev, long seq, long ticks, string user, string action, string? detail,
        string? clientIp)
    {
        Begin(prev);
        Text(Audit); Num(seq); Num(ticks); Text(user); Text(action); Text(detail); Text(clientIp);
        return Finish();
    }

    // The start of a chain; the hash of its first checkpoint
    public byte[] Genesis(string chain, DateTime startedAt, long legacyMaxId, long legacyCount)
    {
        Begin([]);
        Text("genesis"); Text(chain); Num(startedAt.Ticks); Num(legacyMaxId); Num(legacyCount);
        return Finish();
    }

    // Links a checkpoint to the one before it (prevMac), so one cannot be deleted or edited unnoticed
    public byte[] CheckpointMac(ChainCheckpoint c, ReadOnlySpan<byte> prevMac)
    {
        Begin([]);
        Text("checkpoint"); Text(c.Chain); Num(c.UpToSeq); Bytes(c.Hash); Text(c.KeyId); Bytes(prevMac);
        Text(c.Reason); Num(c.DeletedRows); Num(c.CreatedAt.Ticks);
        return Finish();
    }

    // A signature over free text (anchor files, the head file)
    public byte[] Sign(string text)
    {
        Begin([]);
        Text("sign"); Text(text);
        return Finish();
    }

    public static string KeyId(byte[] key) => Convert.ToHexString(SHA256.HashData(key))[..8].ToLowerInvariant();

    public static bool Same(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => CryptographicOperations.FixedTimeEquals(a, b);

    private void Begin(ReadOnlySpan<byte> prefix)
    {
        _len = 0;
        Append(prefix);
        _canonicalStart = _len;
        Append([Version]);
    }

    private byte[] Finish() => _hmac.ComputeHash(_buf, 0, _len);

    private void Ensure(int more)
    {
        if (_len + more > _buf.Length) Array.Resize(ref _buf, Math.Max(_buf.Length * 2, _len + more));
    }

    private void Append(ReadOnlySpan<byte> bytes)
    {
        Ensure(bytes.Length);
        bytes.CopyTo(_buf.AsSpan(_len));
        _len += bytes.Length;
    }

    private void Length(int n)
    {
        Ensure(4);
        BinaryPrimitives.WriteInt32LittleEndian(_buf.AsSpan(_len), n);
        _len += 4;
    }

    private void Text(string? s)
    {
        if (s == null) { Length(-1); return; }
        var n = Encoding.UTF8.GetByteCount(s);
        Length(n);
        Ensure(n);
        Encoding.UTF8.GetBytes(s, _buf.AsSpan(_len));
        _len += n;
    }

    private void Bytes(ReadOnlySpan<byte> b) { Length(b.Length); Append(b); }

    private void Num(long n) => Text(n.ToString(CultureInfo.InvariantCulture));

    private void Flag(bool b) => Text(b ? "1" : "0");
}
