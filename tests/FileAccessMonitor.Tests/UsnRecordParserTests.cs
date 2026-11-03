using System.Buffers.Binary;
using System.Text;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class UsnRecordParserTests
{
    private static readonly DateTime Time = new(2026, 11, 3, 10, 0, 0, DateTimeKind.Utc);

    private static byte[] V2(ulong frn, ulong parent, long usn, uint reason, uint attributes, string name)
    {
        var nameBytes = Encoding.Unicode.GetBytes(name);
        var length = (60 + nameBytes.Length + 7) & ~7;
        var b = new byte[length];
        BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)length);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(4), 2);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(8), frn);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(16), parent);
        BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(24), usn);
        BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(32), Time.ToFileTimeUtc());
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(40), reason);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(52), attributes);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(56), (ushort)nameBytes.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(58), 60);
        nameBytes.CopyTo(b, 60);
        return b;
    }

    private static byte[] V3(ulong frnLow, ulong frnHigh, ulong parentLow, ulong parentHigh, long usn, uint reason, uint attributes, string name)
    {
        var nameBytes = Encoding.Unicode.GetBytes(name);
        var length = (76 + nameBytes.Length + 7) & ~7;
        var b = new byte[length];
        BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)length);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(4), 3);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(8), frnLow);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(16), frnHigh);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(24), parentLow);
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(32), parentHigh);
        BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(40), usn);
        BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(48), Time.ToFileTimeUtc());
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(56), reason);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(68), attributes);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(72), (ushort)nameBytes.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(74), 76);
        nameBytes.CopyTo(b, 76);
        return b;
    }

    private static byte[] Output(long nextUsn, params byte[][] records)
    {
        var all = new List<byte>(BitConverter.GetBytes(nextUsn));
        foreach (var r in records) all.AddRange(r);
        return [.. all];
    }

    [Fact]
    public void Parses_a_v2_record()
    {
        var list = UsnRecordParser.Parse(Output(5000, V2(0x10, 0x20, 4096, UsnReasons.FileCreate, 0x20, "new.txt")), out var next);
        Assert.Equal(5000, next);
        var r = Assert.Single(list);
        Assert.Equal(2, r.MajorVersion);
        Assert.Equal(new UsnFileRef(0x10, 0), r.FileRef);
        Assert.Equal(new UsnFileRef(0x20, 0), r.ParentRef);
        Assert.Equal(4096, r.Usn);
        Assert.Equal(Time, r.TimeUtc);
        Assert.Equal(UsnReasons.FileCreate, r.Reason);
        Assert.Equal("new.txt", r.Name);
        Assert.False(r.IsDirectory);
    }

    [Fact]
    public void Parses_a_v3_record_with_128_bit_references()
    {
        var list = UsnRecordParser.Parse(Output(9000,
            V3(1, 2, 3, 4, 8192, UsnReasons.RenameNewName, UsnReasons.DirectoryAttribute, "Ordner \u00e4\u3042")), out var next);
        Assert.Equal(9000, next);
        var r = Assert.Single(list);
        Assert.Equal(3, r.MajorVersion);
        Assert.Equal(new UsnFileRef(1, 2), r.FileRef);
        Assert.Equal(new UsnFileRef(3, 4), r.ParentRef);
        Assert.Equal(8192, r.Usn);
        Assert.Equal(Time, r.TimeUtc);
        Assert.Equal(UsnReasons.RenameNewName, r.Reason);
        Assert.Equal("Ordner \u00e4\u3042", r.Name);
        Assert.True(r.IsDirectory);
    }

    [Fact]
    public void Parses_several_records_of_mixed_versions()
    {
        var list = UsnRecordParser.Parse(Output(1,
            V2(1, 9, 10, UsnReasons.RenameOldName, 0, "a.txt"),
            V3(2, 0, 9, 0, 11, UsnReasons.RenameNewName, 0, "b.txt"),
            V2(3, 9, 12, UsnReasons.FileCreate, 0, "c")), out _);
        Assert.Equal(["a.txt", "b.txt", "c"], list.Select(r => r.Name));
    }

    [Fact]
    public void Empty_output_has_no_records()
    {
        Assert.Empty(UsnRecordParser.Parse(Output(777), out var next));
        Assert.Equal(777, next);
        Assert.Empty(UsnRecordParser.Parse([], out _));
        Assert.Empty(UsnRecordParser.Parse(new byte[4], out _));
    }

    [Fact]
    public void Unknown_version_and_damaged_records_are_skipped()
    {
        var unknown = V2(1, 2, 3, 0x100, 0, "x");
        BinaryPrimitives.WriteUInt16LittleEndian(unknown.AsSpan(4), 4);
        var good = V2(5, 6, 7, 0x100, 0, "ok.txt");
        var list = UsnRecordParser.Parse(Output(1, unknown, good), out _);
        Assert.Equal("ok.txt", Assert.Single(list).Name);

        // name length points beyond the record
        var damaged = V2(1, 2, 3, 0x100, 0, "x");
        BinaryPrimitives.WriteUInt16LittleEndian(damaged.AsSpan(56), 500);
        Assert.Empty(UsnRecordParser.Parse(Output(1, damaged), out _));

        // truncated buffer: the last record is incomplete
        var cut = Output(1, good)[..^4];
        Assert.Empty(UsnRecordParser.Parse(cut, out _));
    }

    [Theory]
    [InlineData(@"\\?\C:\Data\Dir", @"C:\Data\Dir")]
    [InlineData(@"\\?\UNC\srv\share\x", @"\\srv\share\x")]
    [InlineData(@"C:\plain", @"C:\plain")]
    public void Strips_the_extended_path_prefix(string path, string expected) =>
        Assert.Equal(expected, UsnJournalReader.StripPrefix(path));

    [Theory]
    [InlineData(@"C:\", "a.txt", @"C:\a.txt")]
    [InlineData(@"C:\dir", "a.txt", @"C:\dir\a.txt")]
    [InlineData(@"C:\dir\", "a.txt", @"C:\dir\a.txt")]
    public void Combines_parent_and_name(string parent, string name, string expected) =>
        Assert.Equal(expected, UsnJournalReader.CombinePath(parent, name));

    [Theory]
    [InlineData(@"d:\share", true, "D:")]
    [InlineData(@"E:\", true, "E:")]
    [InlineData(@"\\server\share", false, "")]
    [InlineData(@"relative", false, "")]
    public void Volume_letter_of_a_path(string path, bool ok, string letter)
    {
        Assert.Equal(ok, UsnJournalReader.TryDriveOf(path, out var l));
        Assert.Equal(letter, l);
    }
}
