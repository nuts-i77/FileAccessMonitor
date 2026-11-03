using FileAccessMonitor.Models;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class ChainHashTests
{
    private static readonly byte[] Key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] Prev = new byte[32];

    private static AccessRecord Row() => new()
    {
        ServerName = "FS01", AccessTime = new DateTime(2026, 11, 3, 1, 2, 3, DateTimeKind.Utc).AddTicks(1234567),
        AccessType = "Write", Denied = true, IsFolder = false, UserName = @"CORP\taro", FilePath = @"D:\a\b.txt", FileName = "b.txt",
        FolderPath = @"D:\a", ClientIp = "10.0.0.5", ClientMachine = null, NewPath = null, Detail = "日本語",
    };

    [Fact]
    public void Canonical_form_and_hash_are_stable()
    {
        using var h = new ChainHasher(Key);
        var hash = h.Hash(Prev, 7, Row());
        // version 1, then each field as 4-byte length + UTF-8 (null = -1): a change here breaks every existing chain
        var ticks = Row().AccessTime.Ticks.ToString();
        Assert.Equal(
            "01" + "06000000" + "616363657373" + "01000000" + "37" + "04000000" + "46533031" +
            $"{ticks.Length:x2}000000" + Convert.ToHexString(System.Text.Encoding.ASCII.GetBytes(ticks)).ToLowerInvariant() +
            "05000000" + "5772697465" + "01000000" + "31" + "01000000" + "30" + "09000000" + "434f52505c7461726f" +
            "0a000000" + "443a5c615c622e747874" + "05000000" + "622e747874" + "04000000" + "443a5c61" + "08000000" + "31302e302e302e35" +
            "ffffffff" + "ffffffff" + "09000000" + "e697a5e69cace8aa9e",
            Convert.ToHexString(h.LastCanonical()).ToLowerInvariant());
        Assert.Equal("969357E59BCF2F627627CCC6306F3562", Convert.ToHexString(hash)[..32]);
        Assert.Equal("67CBC0A3BE4F5BB341C4F6C7DBFBC239", Convert.ToHexString(hash)[32..]);
    }

    [Fact]
    public void Same_input_same_hash_and_every_input_matters()
    {
        using var h = new ChainHasher(Key);
        var a = h.Hash(Prev, 7, Row());
        Assert.Equal(a, h.Hash(Prev, 7, Row()));
        Assert.NotEqual(a, h.Hash(Prev, 8, Row()));
        Assert.NotEqual(a, h.Hash(Enumerable.Repeat((byte)1, 32).ToArray(), 7, Row()));
        var r = Row(); r.AccessTime = r.AccessTime.AddTicks(1);
        Assert.NotEqual(a, h.Hash(Prev, 7, r));
        r = Row(); r.Denied = false;
        Assert.NotEqual(a, h.Hash(Prev, 7, r));
        r = Row(); r.IsFolder = true;
        Assert.NotEqual(a, h.Hash(Prev, 7, r));
        using var other = new ChainHasher(Enumerable.Range(2, 32).Select(i => (byte)i).ToArray());
        Assert.NotEqual(a, other.Hash(Prev, 7, Row()));
    }

    [Fact]
    public void Field_boundaries_are_not_ambiguous()
    {
        using var h = new ChainHasher(Key);
        var a = Row(); a.UserName = "ab"; a.FilePath = "c";
        var b = Row(); b.UserName = "a"; b.FilePath = "bc";
        Assert.NotEqual(h.Hash(Prev, 1, a), h.Hash(Prev, 1, b));
        a = Row(); a.FilePath = "x"; a.FileName = "yz";
        b = Row(); b.FilePath = "xy"; b.FileName = "z";
        Assert.NotEqual(h.Hash(Prev, 1, a), h.Hash(Prev, 1, b));
    }

    [Fact]
    public void Null_and_empty_differ()
    {
        using var h = new ChainHasher(Key);
        var a = Row(); a.Detail = null;
        var b = Row(); b.Detail = "";
        Assert.NotEqual(h.Hash(Prev, 1, a), h.Hash(Prev, 1, b));
    }

    [Fact]
    public void Audit_rows_have_their_own_form()
    {
        using var h = new ChainHasher(Key);
        var e = new AuditLogEntry { Time = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), UserName = "admin", Action = "x", Detail = null, ClientIp = "1.2.3.4" };
        var hash = h.Hash(Prev, 1, e);
        e.Detail = "";
        Assert.NotEqual(hash, h.Hash(Prev, 1, e));
        e.Detail = null;
        e.Action = "y";
        Assert.NotEqual(hash, h.Hash(Prev, 1, e));
    }

    [Fact]
    public void Checkpoint_mac_covers_the_checkpoint_before_it()
    {
        using var h = new ChainHasher(Key);
        var c = new ChainCheckpoint { Chain = "access", UpToSeq = 5, Hash = new byte[32], Reason = "retention", DeletedRows = 5, KeyId = "abcd", CreatedAt = DateTime.UtcNow };
        var a = h.CheckpointMac(c, new byte[32]);
        Assert.Equal(a, h.CheckpointMac(c, new byte[32]));
        Assert.NotEqual(a, h.CheckpointMac(c, Enumerable.Repeat((byte)9, 32).ToArray()));
        c.DeletedRows = 6;
        Assert.NotEqual(a, h.CheckpointMac(c, new byte[32]));
    }

    [Fact]
    public void Key_id_is_eight_hex_characters() => Assert.Matches("^[0-9a-f]{8}$", ChainHasher.KeyId(Key));
}
