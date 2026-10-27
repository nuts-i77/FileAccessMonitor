using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class AccessMaskTests
{
    [Theory]
    [InlineData("0x1", "Read")]              // ReadData
    [InlineData("0x80000000", "Read")]       // GENERIC_READ
    [InlineData("0x120089", "Read")]         // typical "open for read" (ReadData|ReadEA|ReadAttributes|READ_CONTROL|SYNCHRONIZE)
    [InlineData("0x2", "Write")]             // WriteData
    [InlineData("0x4", "Write")]             // AppendData
    [InlineData("0x40000000", "Write")]      // GENERIC_WRITE
    [InlineData("0x3", "Write")]             // Read + Write counts as Write
    [InlineData("0x10000", "Delete")]        // DELETE
    [InlineData("0x10003", "Delete")]        // DELETE wins over Read/Write
    [InlineData("0X1", "Read")]              // upper-case prefix
    [InlineData("1", "Read")]                // decimal
    public void Classifies_access_mask(string mask, string expected) =>
        Assert.Equal(expected, EventLogCollectorService.ParseAccessType(mask));

    [Theory]
    [InlineData("0x80")]      // ReadAttributes only (e.g. a backup tool checking timestamps)
    [InlineData("0x100")]     // WriteAttributes only
    [InlineData("0x8")]       // ReadEA
    [InlineData("0x10")]      // WriteEA
    [InlineData("0x20000")]   // READ_CONTROL
    [InlineData("0x0")]
    [InlineData("")]
    [InlineData("-")]
    [InlineData("0xZZ")]
    public void Ignores_metadata_only_or_invalid_masks(string mask) =>
        Assert.Null(EventLogCollectorService.ParseAccessType(mask));
}
